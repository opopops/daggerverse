from typing import Annotated, Self
import dagger
from dagger import Doc, dag, function, object_type


@object_type
class Grype:
    """Grype CLI"""

    image: str
    version: str
    user: str
    container_: dagger.Container | None

    @classmethod
    async def create(
        cls,
        image: Annotated[str | None, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str | None, Doc("Grype version")] = "0.104.3",
        user: Annotated[str | None, Doc("Image user")] = "65532",
    ):
        """Constructor"""
        return cls(image=image, version=version, user=user, container_=None)

    @function
    def container(self) -> dagger.Container:
        """Returns configured grype container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()

        pkg = "grype"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "docker-cli", pkg])
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_env_variable("DOCKER_HOST", "unix:///tmp/docker.sock")
            .with_env_variable("GRYPE_CACHE_DIR", "/cache/grype")
            .with_env_variable(
                "GRYPE_DB_CACHE_DIR", "${GRYPE_CACHE_DIR}/db", expand=True
            )
            .with_env_variable("GRYPE_WORK_DIR", "/grype")
            .with_mounted_cache(
                "$GRYPE_CACHE_DIR",
                dag.cache_volume("grype-cache"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=self.user,
                expand=True,
            )
            .with_user(self.user)
            .with_exec(["mkdir", "-p", "$DOCKER_CONFIG"], expand=True)
            .with_new_file(
                "${DOCKER_CONFIG}/config.json",
                contents="",
                owner=self.user,
                permissions=0o600,
                expand=True,
            )
            .with_workdir("$GRYPE_WORK_DIR", expand=True)
            .with_entrypoint(["/usr/bin/grype"])
        )

        return self.container_

    @function
    def with_docker_socket(
        self,
        source: Annotated[
            dagger.Socket, Doc("Identifier of the Docker socket to forward")
        ],
    ) -> Self:
        """Retrieves this Apko CLI plus a socket forwarded to the given Unix socket path"""
        self.container_ = self.container().with_unix_socket(
            path="/tmp/docker.sock", source=source, owner=self.user
        )
        return self

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        container: dagger.Container = self.container()
        cmd = [
            "sh",
            "-c",
            (
                f"docker login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.container_ = container.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

    @function
    def docker_config(self) -> dagger.File:
        """Returns the Docker config file"""
        return self.container().file("${DOCKER_CONFIG}/config.json", expand=True)

    @function
    def with_docker_config(
        self, docker_config: Annotated[dagger.File, Doc("Docker config file")]
    ) -> Self:
        """Set Docker config file (for chaining)"""
        self.container_ = self.container().with_file(
            "${DOCKER_CONFIG}/config.json",
            source=docker_config,
            owner=self.user,
            permissions=0o600,
            expand=True,
        )
        return self

    @function
    def scan(
        self,
        source: Annotated[str, Doc("Source to scan")],
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> dagger.File:
        """Scan"""
        output_file = f"report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [source, "--output", output_format, "--file", output_file]

        if severity:
            cmd.extend(["--fail-on", severity])

        container: dagger.Container = self.container()
        container = container.with_exec(cmd, use_entrypoint=True, expect=expect)
        return container.file(output_file)

    @function
    def with_scan(
        self,
        source: Annotated[str, Doc("Source to scan")],
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan (for chaining)"""
        self.scan(
            source=source, severity=severity, fail=fail, output_format=output_format
        )
        return self

    @function
    def scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "registry",
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> dagger.File:
        """Scan container image"""
        output_file = f"report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [
            f"{source_type}:{source}",
            "--output",
            output_format,
            "--file",
            output_file,
        ]

        if severity:
            cmd.extend(["--fail-on", severity])

        container: dagger.Container = self.container()
        container = container.with_exec(cmd, use_entrypoint=True, expect=expect)
        return container.file(output_file)

    @function
    def with_scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "registry",
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan container image (for chaining)"""
        self.scan_image(
            source=source,
            source_type=source_type,
            severity=severity,
            fail=fail,
            output_format=output_format,
        )
        return self

    @function
    def scan_directory(
        self,
        source: Annotated[dagger.Directory, Doc("Directory to scan")],
        source_type: Annotated[str | None, Doc("Source type")] | None = "dir",
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> dagger.File:
        """Scan directory"""
        output_file = f"report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [
            f"{source_type}:/tmp/directory",
            "--output",
            output_format,
            "--file",
            output_file,
        ]

        if severity:
            cmd.extend(["--fail-on", severity])

        container: dagger.Container = (
            self.container()
            .with_mounted_directory(
                path="/tmp/directory", source=source, owner=self.user, expand=True
            )
            .with_exec(cmd, use_entrypoint=True, expect=expect)
        )
        return container.file(output_file)

    @function
    def with_scan_directory(
        self,
        source: Annotated[dagger.Directory, Doc("Directory to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "registry",
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan dir (for chaining)"""
        self.scan_directory(
            source=source,
            source_type=source_type,
            severity=severity,
            fail=fail,
            output_format=output_format,
        )
        return self

    @function
    def scan_file(
        self,
        source: Annotated[dagger.File, Doc("File to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "file",
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> dagger.File:
        """Scan file"""
        output_file = f"report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [
            f"{source_type}:/tmp/file",
            "--output",
            output_format,
            "--file",
            output_file,
        ]

        if severity:
            cmd.extend(["--fail-on", severity])

        container: dagger.Container = (
            self.container()
            .with_file(path="/tmp/file", source=source, owner=self.user, expand=True)
            .with_exec(cmd, use_entrypoint=True, expect=expect)
        )
        return container.file(output_file)

    @function
    def with_scan_file(
        self,
        source: Annotated[dagger.File, Doc("File to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "registry",
        severity: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
        ) = "",
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan file (for chaining)"""
        self.scan_file(
            source=source,
            source_type=source_type,
            severity=severity,
            fail=fail,
            output_format=output_format,
        )
        return self
