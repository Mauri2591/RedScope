sudo apt update && sudo apt install -y \
  whois \
  dnsutils \
  geoip-bin \
  curl \
  nmap

# Go tools (necesarios para subfinder y waybackurls)
sudo apt install -y golang-go

# Instalar subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Instalar waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Agregar Go binaries al PATH si no está
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc