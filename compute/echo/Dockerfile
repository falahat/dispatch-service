FROM python:3.13-slim

# Reference compute container for the INVOKE contract v0. Standard library only — no pip.
WORKDIR /app
COPY app.py /app/app.py

# Run as a non-root user.
RUN useradd --create-home --uid 10001 echo
USER echo

ENV INVOKE_ADDR=0.0.0.0:8080
EXPOSE 8080

# Readiness probe hits the same endpoint the runner polls at boot.
HEALTHCHECK --interval=10s --timeout=3s --start-period=2s --retries=3 \
  CMD python -c "import os,urllib.request,sys; p=os.environ.get('INVOKE_ADDR','0.0.0.0:8080').rsplit(':',1)[1]; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+p+'/healthz',timeout=2).status==200 else 1)"

CMD ["python", "/app/app.py"]
