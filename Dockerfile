FROM rust:slim-buster as builder

RUN apt-get update && apt-get install -y \
  libssl-dev \
  pkg-config \
  libglib2.0-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN USER=root cargo new --bin pelipper-post-office
WORKDIR /src/pelipper-post-office
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN cargo build --release  # collects dependencies
RUN rm src/*.rs  # removes the `cargo new` generated files.

ADD . ./

RUN rm ./target/release/deps/pelipper_post_office*

RUN cargo build --release
RUN strip /src/pelipper-post-office/target/release/pelipper-post-office


FROM rust:slim-buster as build

ARG APP=/usr/src/app

EXPOSE 34434

ENV TZ=Etc/UTC \
    APP_USER=pelipper

RUN adduser --system --group $APP_USER

RUN apt-get update && apt-get install -y \
  ca-certificates \
  tzdata \
  && rm -rf /var/lib/apt/lists/*


COPY --from=builder /src/pelipper-post-office/target/release/pelipper-post-office ${APP}/pelipper-post-office

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

STOPSIGNAL SIGINT

ENTRYPOINT ["./pelipper-post-office"]
