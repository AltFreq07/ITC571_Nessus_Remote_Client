# ITC571_Nessus_Remote_Client

## Windows Build
```
go run github.com/tc-hib/go-winres make
GOOS=windows GOARCH=amd64 go build -o "Nessus Remote Scanner.exe"
```

## Linux Build
```
GOOS=linux GOARCH=amd64 go build -o Nessus_Remote_Scanner_linux client.go permissions_unix.go nessus_setup_windows.go
```

## MacOSX Build
```
GOOS=darwin GOARCH=amd64 go build -o Nessus_Remote_Scanner_macos client.go permissions_unix.go nessus_setup_windows.go
mkdir -p Nessus_Remote_Scanner_macos.app/Contents/MacOS
mkdir -p Nessus_Remote_Scanner_macos.app/Contents/Resources
cp Nessus_Remote_Scanner_macos Nessus_Remote_Scanner_macos.app/Contents/MacOS/
cp Info.plist Nessus_Remote_Scanner_macos.app/Contents/
```