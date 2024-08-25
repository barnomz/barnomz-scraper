package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/joho/godotenv"
)

var watchedDepartments = map[int]string{
	20: "مهندسی_عمران",
	21: "مهندسی_صنایع",
	22: "علوم_ریاضی",
	23: "شیمی",
	24: "فیزیک",
	25: "مهندسی_برق",
	26: "مهندسی_شیمی_و_نفت",
	27: "مهندسی_و_علم_مواد",
	28: "مهندسی_مکانیک",
	29: "پژوهشکده_سیاست‏گذاری_علم،_فناوری_و_صنعت",
	30: "مرکز_تربیت_بدنی",
	31: "مرکز_زبان‌ها_و_زبان‌شناسی",
	33: "مرکز_آموزش_مهارت‌های_مهندسی",
	34: "پژوهشکده_علوم_و_فن‌آوری_انرژی،_آب_و_محیط_زیست",
	35: "مرکز_گرافیک_(مرکز_آموزش_مهارت‌های_مهندسی)",
	37: "مرکز_معارف_اسلامی_و_علوم_انسانی",
	38: "بیوشیمی",
	39: "پژوهشکده_الکترونيک",
	40: "مهندسی_کامپیوتر",
	41: "گروه_برنامه‌ریزی_سیستم‌ها",
	42: "گروه_فلسفه_علم",
	43: "مهندسی_سیستم‌های_انرژی",
	44: "مدیریت_و_اقتصاد",
	45: "مهندسی_هوافضا",
	46: "مهندسی_انرژی",
	47: "پژوهشکده_فناوری_اطلاعات_و_ارتباطات_پیشرفته",
	48: "پژوهشکده_علوم_و_فن‌آوری_نانو",
	49: "طرح_مهمان_تکدرس",
	50: "دروس_پایه_و_عمومی_(پردیس_کیش)",
	51: "مهندسی_صنایع_(پردیس_کیش)",
	52: "مهندسی_کامپیوتر_(پردیس_کیش)",
	53: "مهندسی_عمران_(پردیس_کیش)",
	54: "مدیریت_(پردیس_کیش)",
	55: "مهندسی_برق_(پردیس_کیش)",
	56: "مهندسی_نانوفناوری_(پردیس_کیش)",
	57: "مهندسی_مواد_(پردیس_کیش)",
	58: "مهندسی_مکانیک_(پردیس_کیش)",
	59: "زبان‌ها_و_زبان‌شناسی_(پردیس_کیش)",
	61: "طرح_مهمان_تک_درس_(پردیس_کیش)",
	65: "مهندسی_هوافضا_(پردیس_کیش)",
	66: "مهندسی_شیمی_و_نفت_(پردیس_کیش)",
	70: "دروس_پایه_و_عمومی_(پردیس_تهران)",
	71: "طرح_مهمان_تک_درس_(پردیس_تهران)",
	73: "مهندسی_عمران_(پردیس_تهران)",
	76: "مهندسی_نفت_(پردیس_تهران)",
	77: "مهندسی_مواد_(پردیس_تهران)",
	78: "مهندسی_مکانیک_(پردیس_تهران)",
	79: "مهندسی_مکاترونیک_(پردیس_تهران)",
	80: "مهندسی_فناوری_اطلاعات_(پردیس_تهران)",
	81: "مهندسی_کامپیوتر(پردیس_تهران)",
}

var dayOfWeekMap = map[string]int{
	"شنبه":     0,
	"یکشنبه":   1,
	"دوشنبه":   2,
	"سه شنبه":  3,
	"چهارشنبه": 4,
	"پنجشنبه":  5,
	"جمعه":     6,
}

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

var EduUsername string
var EduPassword string

type Course struct {
	Code           string
	Group          int
	Name           string
	Lecturer       string
	Capacity       int
	Registered     int
	Units          int
	ExamDate       *string
	ExamTime       *string
	DaysOfWeek     []int
	StartTime      *string
	EndTime        *string
	Info           *string
	Department     string
	DepartmentCode int
	Grade		   string
}

type StatusCodeError struct {
	ReceivedStatusCode int
}

func (e StatusCodeError) Error() string {
	return "unexpected status code " + strconv.Itoa(e.ReceivedStatusCode)
}

// IsServerError checks if the server has fucked up
func IsServerError(err error) bool {
	unwrapped, ok := err.(StatusCodeError)
	return ok && unwrapped.ReceivedStatusCode >= 500
}

func trimAndNilIfEmpty(s string) *string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

var Courses = make(map[string]Course)
var httpClient *http.Client
var errorLogin = errors.New("redirected to login page")

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
	EduUsername = os.Getenv("EDU_USERNAME")
	EduPassword = os.Getenv("EDU_PASSWORD")
}

func main() {
	// Check startup restore
	if len(os.Args) > 1 {
		file, err := os.Open(os.Args[1])
		if err != nil {
			log.Fatalln("cannot open file:", err)
		}
		err = json.NewDecoder(file).Decode(&Courses)
		if err != nil {
			log.Fatalln("cannot unmarshal json:", err)
		}
		_ = file.Close()
	}

	http.HandleFunc("/", serveLatestCourses)
	http.HandleFunc("/start", handleStart) // New handler for POST requests

	go func() {
		log.Println("Starting server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	period := os.Getenv("PERIOD")
	d, err := time.ParseDuration(period)
	if err != nil {
		log.Fatalf("Invalid period format: %v", err)
	}
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	log.Println("Running Start immediately")
	err = Start(ctx)
	if err != nil {
		log.Println("Start error:", err)
	}

	for {
		select {
		case <-ticker.C:
			log.Println("Running Start due to tick")
			err := Start(ctx)
			if err != nil {
				log.Println("fatal error:", err)
			}
		case <-ctx.Done():
			log.Println("Shutting down due to signal")
			return
		}
	}
}

func serveLatestCourses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, _ := json.Marshal(Courses)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	EduUsername = creds.Username
	EduPassword = creds.Password

	ctx := r.Context()
	err = Start(ctx)
	if err != nil {
		http.Error(w, "Failed to start scraping: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Scraping started successfully"))
}

func Start(ctx context.Context) (err error) {
	for {
		err = Login(ctx)
		if err == nil {
			break
		} else {
			log.Println("cannot login:", err)
		}
		time.Sleep(time.Second * 10)
	}
	log.Println("login done")
	// for {
	for depID, depName := range watchedDepartments {
		var gotCourses int
		log.Println("getting courses of", depID)
		gotCourses, err = CheckDiff(ctx, depID, depName)
		if err != nil {
			log.Println("cannot get the courses for", depID, err)
			return err
		}
		log.Println("scrapped department", depID, "with", gotCourses, "courses")
		select {
		case <-time.After(time.Second * 5):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	log.Println("currently have", len(Courses), "courses")
	return nil
}

func CheckDiff(ctx context.Context, departmentID int, departmentName string) (int, error) {
	// Do the request
	resp, err := httpClient.Do(GetRequest(ctx, "POST", "https://edu.sharif.edu/register.do",
		strings.NewReader(url.Values{"level": {"0"}, "teacher_name": {""}, "sort_item": {"1"}, "depID": {strconv.Itoa(departmentID)}}.Encode())))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Check status
	if resp.StatusCode != http.StatusOK {
		return 0, StatusCodeError{resp.StatusCode}
	}
	// Read html
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return 0, err
	}
	// Check login page
	doc.Find("title").Each(func(i int, selection *goquery.Selection) {
		if selection.Text() == "سامانه آموزش - دانشگاه صنعتی شریف" {
			err = errorLogin
		}
	})
	if err != nil {
		return 0, err
	}
	// Get the table
	var coursesGot int
	doc.Find(".contentTable").Each(func(tableI int, table *goquery.Selection) {
		var grade string
		// Find the grade based on the first tr in the tbody
		table.Find("tbody tr").First().Find("td").Each(func(_ int, column *goquery.Selection) {
			text := strings.TrimSpace(column.Text())
			if strings.Contains(text, "کارشناسی ارشد") {
				grade = "ms"
			} else if strings.Contains(text, "دکترا") {
				grade = "phd"
			} else {
				grade = "bs"
			}
		})

		// Loop each row
		table.Find("tr").Each(func(_ int, row *goquery.Selection) {
			var course Course
			var ok bool
			row.Find("td").Each(func(i int, column *goquery.Selection) {
				text := strings.Trim(column.Text(), " ")
				// Try to parse the course main ID to see if this is a valid row or not
				if i == 0 {
					_, err := strconv.Atoi(text)
					ok = err == nil
				}
				// If this row is not ok, just return and don't do anything
				if !ok {
					return
				}
				// Now check the index
				switch i {
				case 0: // course ID
					course.Code = text
				case 1: // course group
					course.Group, _ = strconv.Atoi(text)
				case 2: // units
					course.Units, _ = strconv.Atoi(text)
				case 3: // name of course
					course.Name = text
				case 5: // total capacity
					course.Capacity, _ = strconv.Atoi(text)
				case 6:
					course.Registered, _ = strconv.Atoi(text)
				case 7: // Lecturer name
					course.Lecturer = text
				case 8: // Exam date
					examDate, examTime := ParseExamDateTime(text)
					course.ExamDate = trimAndNilIfEmpty(examDate)
					course.ExamTime = trimAndNilIfEmpty(examTime)
				case 9: // Schedule
					daysOfWeek, startTime, endTime := ParseCourseSchedule(text)
					course.DaysOfWeek = daysOfWeek
					course.StartTime = trimAndNilIfEmpty(startTime)
					course.EndTime = trimAndNilIfEmpty(endTime)
				case 11: // Info
					course.Info = trimAndNilIfEmpty(text)
				}
			})
			// If we couldn't get this row, just return
			if !ok {
				return
			}
			// Set the course grade
			course.Grade = grade
			// replace the _ with space in departmentName
			course.Department = strings.Replace(departmentName, "_", " ", -1)
			course.DepartmentCode = departmentID
			// Replace the old course
			Courses[fmt.Sprintf("%s-%d", course.Code, course.Group)] = course
			coursesGot++
		})
	})
	return coursesGot, nil
}


func Login(ctx context.Context) error {
	jar, _ := cookiejar.New(nil)
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}
	resp, err := httpClient.Do(GetRequest(ctx, "GET", "https://edu.sharif.edu/", nil))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return StatusCodeError{ReceivedStatusCode: resp.StatusCode}
	}
	// Get body
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	// Login
	req := GetRequest(ctx, "POST", "https://edu.sharif.edu/login.do", strings.NewReader(url.Values{
		"username":         {EduUsername},
		"password":         {EduPassword},
		"jcaptcha":         {"ab"},
		"command":          {"login"},
		"captcha_key_name": {"ab"}, "captchaStatus": {"ab"},
	}.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	time.Sleep(time.Second)
	resp, err = httpClient.Do(req)
	if err != nil {
		return err
	}
	// Check status code
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte("خروج")) {
		return errors.New("body is invalid")
	}
	return WarmUp(ctx)
}

func WarmUp(ctx context.Context) error {
	// Open the menu
	resp, err := httpClient.Do(GetRequest(ctx, "POST", "https://edu.sharif.edu/action.do",
		strings.NewReader(url.Values{"changeMenu": {"OnlineRegistration"}, "isShowMenu": {""}, "commandMessage": {""}, "defaultCss": {""}}.Encode())))
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return StatusCodeError{resp.StatusCode}
	}
	if IsLogin(body) {
		return errorLogin
	}
	// Change to courses
	resp, err = httpClient.Do(GetRequest(ctx, "POST", "https://edu.sharif.edu/register.do",
		strings.NewReader(url.Values{"changeMenu": {"OnlineRegistration*OfficalLessonListShow"}, "isShowMenu": {""}}.Encode())))
	if err != nil {
		return err
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return StatusCodeError{resp.StatusCode}
	}
	if IsLogin(body) {
		return errorLogin
	}
	return nil
}

func GetRequest(ctx context.Context, method, url string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, url, body)
	req = req.WithContext(ctx)
	req.Header.Set("user-agent", UserAgent)
	if method == "POST" {
		req.Header.Set("content-type", "application/x-www-form-urlencoded")
	}
	return req
}

func IsLogin(body []byte) bool {
	return bytes.Contains(body, []byte("https://accounts.sharif.edu/cas/login?service=https://edu.sharif.edu/login.jsp"))
}

func ParseCourseSchedule(input string) ([]int, string, string) {
	// Regex to extract the days, start time, and end time
	re := regexp.MustCompile(`(?P<days>[^\d]+) از (?P<start>\d{1,2}:\d{1,2}) تا (?P<end>\d{1,2}:\d{1,2})`)
	matches := re.FindStringSubmatch(input)

	// Map to hold the names of matched groups
	groupNames := re.SubexpNames()

	result := make(map[string]string)
	for i, match := range matches {
		result[groupNames[i]] = match
	}

	days := strings.Split(result["days"], " و ")
	daysOfWeek := make([]int, 0, len(days))
	for _, day := range days {
		if dayNum, exists := dayOfWeekMap[strings.TrimSpace(day)]; exists {
			daysOfWeek = append(daysOfWeek, dayNum)
		}
	}

	// Add missing zero to time format if necessary
	startTime := fixTimeFormat(result["start"])
	endTime := fixTimeFormat(result["end"])

	return daysOfWeek, startTime, endTime
}

func fixTimeFormat(timeStr string) string {
	parts := strings.Split(timeStr, ":")
	if len(parts) == 2 {
		if len(parts[0]) == 1 {
			parts[0] = "0" + parts[0]
		}
		if len(parts[1]) == 1 {
			parts[1] = parts[1] + "0"
		}
		return parts[0] + ":" + parts[1]
	}
	return timeStr
}

func ParseExamDateTime(input string) (string, string) {
	re := regexp.MustCompile(`(?P<date>\S+)\s*(?P<time>\d{2}:\d{2})`)
	matches := re.FindStringSubmatch(input)

	// Map to hold the names of matched groups
	groupNames := re.SubexpNames()

	result := make(map[string]string)
	for i := 1; i < len(matches); i++ {
		result[groupNames[i]] = matches[i]
	}

	return result["date"], result["time"]
}
