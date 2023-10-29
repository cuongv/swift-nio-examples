
# Define your proxy server and port
proxy_server="127.0.0.1"
proxy_port="8080"

# Set the proxy for HTTP and HTTPS
networksetup -setwebproxy Wi-Fi $proxy_server $proxy_port
networksetup -setsecurewebproxy Wi-Fi $proxy_server $proxy_port


if [ "$1" == "off" ]; then
  networksetup -setwebproxystate Wi-Fi off
  networksetup -setsecurewebproxystate Wi-Fi off
  echo "Proxy is now off."
else
  networksetup -setwebproxystate Wi-Fi on
  #networksetup -setsecurewebproxystate Wi-Fi on
  echo "Proxy is now on."
fi

