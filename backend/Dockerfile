FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan dnsutils curl wget unzip git perl \
    libnet-ssleay-perl libjson-perl libxml-writer-perl && \
    rm -rf /var/lib/apt/lists/*

# Install Nikto from source
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Install Nuclei
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)_linux_amd64.zip -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip || true

# Preload Nuclei templates into the image so Celery workers can scan immediately.
RUN nuclei -update-templates || true

# Install Subfinder
RUN curl -sL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(curl -sL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)_linux_amd64.zip -o /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /usr/local/bin/ && rm /tmp/subfinder.zip || true

# Install Amass
RUN set -e; \
        AMASS_URL=$(curl -sL https://api.github.com/repos/owasp-amass/amass/releases/latest | \
            grep 'browser_download_url.*amass_linux_amd64.tar.gz' | head -n1 | cut -d '"' -f4); \
        test -n "$AMASS_URL"; \
        curl -sL "$AMASS_URL" -o /tmp/amass.tar.gz; \
        mkdir -p /tmp/amass; \
        tar -xzf /tmp/amass.tar.gz -C /tmp/amass; \
        install -m 0755 /tmp/amass/amass_linux_amd64/amass /usr/local/bin/amass; \
        rm -rf /tmp/amass /tmp/amass.tar.gz

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
