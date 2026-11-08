
# CSC API demo (compose project csc-demo in /opt/csc-demo, see its DEPLOY.md)
# Add A records for "csc" and "cscweb" pointing to the VPS IP.
csc.decodificat.ro {
    reverse_proxy csc-server:8080
}

cscweb.decodificat.ro {
    # PDFs up to 10 MB are uploaded to the web app
    request_body {
        max_size 12MB
    }
    reverse_proxy csc-webapp:8000
}
