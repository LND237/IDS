1.Install wsl with debian distro which is the server.
2.on the bash write `sudo apt update && sudo apt upgrade`
3.`sudo apt install nginx`
4.`sudo nano /etc/nginx/nginx.conf` in order to configure the nginx software.
5.`sudo service nginx restart` to apply the new configurations.
6. since wsl allows to access the debian files from windows we can install rustrover (IDE for rust)
on windows and work on the files from the proxy server (debian).
7.on the rustrover terminal do `cargo add hyper` and `cargo add tokio` for the poc code.
8.run the code.
9.go to the windows settings to connect to the proxy.
10.go to the cmd and type 'ipconfig' and see the ipv4 of the wsl network interface.
11.in the connection to the proxy type the ip and port 80 and allow local addresses.
12. you should see a notification from the wsl, you are connected!
13.type google.com:80 and should see hello world and in the rustrover 'packet incoming' from the proxy ip.
