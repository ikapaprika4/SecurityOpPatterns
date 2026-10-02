# The whole SOC toolkit in one image: evtxkit, phishkit, nsmkit, trafkit,
# headless triage and the web UI. Standard library only: nothing is installed
# with pip, so the build needs no network beyond the base image.
#
#   docker build -t socscript .
#   docker run --rm socscript                                   # usage
#   docker run --rm socscript evtxkit rules
#   docker run --rm -v "$PWD/evidence:/evidence:ro" -v "$PWD/out:/out" \
#              socscript triage /evidence -o /out               # exit 1 on high/critical
#   docker run --rm -p 127.0.0.1:8765:8765 socscript workbench  # open the printed ?t= link
#
# Dockerfile.evtxkit builds the smaller evtxkit-only image used on Fargate.
FROM python:3.12-slim

# SOCWB_HOST: a published port arrives on the container's network interface,
# never on its loopback, so inside a container the web UI listens on all of
# them. That switches it to "exposed" mode: the page only opens through the
# token link it prints (see socworkbench/server.py).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOCWB_HOST=0.0.0.0 \
    SOCWB_PORT=8765

# Evidence is attacker-supplied: never parse it as root.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin soc

WORKDIR /app
COPY soccore/ ./soccore/
COPY evtxkit/ ./evtxkit/
COPY phishkit/ ./phishkit/
COPY nsmkit/ ./nsmkit/
COPY trafkit/ ./trafkit/
COPY socworkbench/ ./socworkbench/
COPY samples/ ./samples/
# tests/ and tools/ make `socscript selftest` work inside the image.
COPY tests/ ./tests/
COPY tools/ ./tools/
COPY socscript.py run_tests.py ./

USER soc
EXPOSE 8765
ENTRYPOINT ["python", "-m", "socscript"]
CMD ["--help"]
