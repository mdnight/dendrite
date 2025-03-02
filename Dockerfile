FROM golang:1.24-bookworm as build
RUN apt-get update && apt-get install -y postgresql
WORKDIR /build
ARG BINARY

# Copy the build context to the repo as this is the right dendrite code. This is different to the
# Complement Dockerfile which wgets a branch.
COPY . .

RUN go build ./cmd/${BINARY}
RUN go build ./cmd/generate-keys
RUN go build ./cmd/generate-config
RUN go build ./cmd/create-account
RUN ./generate-config --ci > dendrite.yaml
RUN ./generate-keys --private-key matrix_key.pem --tls-cert server.crt --tls-key server.key

# Make sure the SQLite databases are in a persistent location, we're already mapping
# the postgresql folder so let's just use that for simplicity
RUN sed -i "s%connection_string:.file:%connection_string: file:\/var\/lib\/postgresql\/15\/main\/%g" dendrite.yaml

# This entry script starts postgres, waits for it to be up then starts dendrite
RUN echo '\
sed -i "s/server_name: localhost/server_name: ${SERVER_NAME}/g" dendrite.yaml \n\
PARAMS="--tls-cert server.crt --tls-key server.key --config dendrite.yaml" \n\
./${BINARY} --really-enable-open-registration ${PARAMS} || ./${BINARY} ${PARAMS} \n\
' > run_dendrite.sh && chmod +x run_dendrite.sh

ENV SERVER_NAME=localhost
ENV BINARY=dendrite
EXPOSE 8008 8448
CMD /build/run_dendrite.sh
