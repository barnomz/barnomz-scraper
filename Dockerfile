# Use a minimal base image with golang 1.17 installed
FROM golang:1.20

# Set the working directory inside the container
# This is where the application files will be copied and executed
WORKDIR /app

# Copy the Go application files into the container
# This includes the main.go, go.mod, and go.sum files
COPY . .

# Build the Go application
# This will download the dependencies, tidy the go.mod file, and compile the executable
RUN go mod download
RUN go mod tidy
RUN go build -o main .

# Expose port 8080
# This is the port that the application listens on
EXPOSE 8080

# Command to run the Go application
# This will start the application when the container launches
CMD ["./main"]