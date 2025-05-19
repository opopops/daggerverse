from typing import Annotated, Self

import dagger
from dagger import Doc, dag, field, function, object_type


@object_type
class Cli:
    """Apko CLI"""

    image: str = field()
    user: str = field()
    version: str = field()
    workdir: dagger.Directory

    container_: dagger.Container | None = None

    @function
    def container(self) -> dagger.Container:
        """Returns the container"""
        if self.container_:
            return self.container_

        pkg = "docker-cli"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            dag.container()
            .from_(address=self.image)
            .with_env_variable("DOCKER_WORK_DIR", "/tmp/work")
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_env_variable("DOCKER_HOST", "unix:///tmp/docker.sock")
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", pkg])
            .with_entrypoint(["/usr/bin/docker"])
            .with_user(self.user)
            .with_exec(
                ["mkdir", "-p", "$DOCKER_CONFIG"], use_entrypoint=False, expand=True
            )
            .with_new_file(
                "${DOCKER_CONFIG}/config.json",
                contents="",
                owner=self.user,
                permissions=0o600,
                expand=True,
            )
            .with_mounted_directory(
                path="$DOCKER_WORK_DIR",
                source=self.workdir,
                owner=self.user,
                expand=True,
            )
            .with_workdir("$DOCKER_WORK_DIR", expand=True)
        )
        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticates with registry"""
        cmd = [
            "sh",
            "-c",
            (
                f"docker login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.container_ = (
            self.container()
            .with_secret_variable("REGISTRY_PASSWORD", secret)
            .with_exec(cmd, use_entrypoint=False)
        )
        return self

    @function
    def with_env_variable(
        self,
        name: Annotated[str, Doc("Name of the environment variable")],
        value: Annotated[str, Doc("Value of the environment variable")],
        expand: Annotated[
            bool | None,
            Doc(
                "Replace “${VAR}” or “$VAR” in the value according to the current environment variables defined in the container"
            ),
        ] = False,
    ) -> Self:
        """Set a new environment variable in the Apko container"""
        self.container_ = self.container().with_env_variable(
            name=name, value=value, expand=expand
        )
        return self

    @function
    def with_secret_variable(
        self,
        name: Annotated[str, Doc("Name of the secret variable")],
        secret: Annotated[dagger.Secret, Doc("Identifier of the secret value")],
    ) -> Self:
        """Set a new environment variable, using a secret value"""
        self.container_ = self.container().with_secret_variable(
            name=name, secret=secret
        )
        return self

    @function
    def with_unix_socket(
        self,
        source: Annotated[dagger.Socket, Doc("Identifier of the socket to forward")],
    ) -> Self:
        """Retrieves this Apko CLI plus a socket forwarded to the given Unix socket path"""
        self.container_ = self.container().with_unix_socket(
            path="/tmp/docker.sock", source=source, owner=self.user
        )
        return self
