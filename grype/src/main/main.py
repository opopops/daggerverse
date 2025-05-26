from typing import Annotated, Self
import dagger
from dagger import Doc, dag, function, object_type


@object_type
class Grype:
    """Grype CLI"""

    image: str
    version: str
    user: str
    docker_config: dagger.File | None
    container_: dagger.Container | None

    @classmethod
    async def create(
        cls,
        image: Annotated[str | None, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str | None, Doc("Grype version")] = "latest",
        user: Annotated[str | None, Doc("Image user")] = "65532",
        docker_config: Annotated[dagger.File | None, Doc("Docker config file")] = None,
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
            docker_config=docker_config,
            container_=None,
        )

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
            .with_workdir("$DOCKER_CONFIG", expand=True)
            .with_new_file(
                "config.json", contents="", owner=self.user, permissions=0o600
            )
            .with_workdir("$GRYPE_WORK_DIR", expand=True)
            .with_entrypoint(["/usr/bin/grype"])
        )

        if self.docker_config:
            self.container_ = self.container_.with_file(
                "${DOCKER_CONFIG}/config.json",
                source=self.docker_config,
                owner=self.user,
                permissions=0o600,
                expand=True,
            )

        return self.container_

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
    def with_docker_config(
        self, docker_config: Annotated[dagger.File, Doc("Docker config file")]
    ) -> Self:
        """Set Docker config file (for chaining)"""
        self.container_ = self.container().with_mounted_file(
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
        severity_cutoff: (
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
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan"""
        output_file = f"report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [source, "--output", output_format, "--file", output_file]

        if severity_cutoff:
            cmd.extend(["--fail-on", severity_cutoff])

        container: dagger.Container = self.container()
        container = container.with_exec(cmd, use_entrypoint=True, expect=expect)
        return container.file(output_file)

    @function
    def with_scan(
        self,
        source: Annotated[str, Doc("Source to scan")],
        severity_cutoff: (
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
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan (for chaining)"""
        self.scan(
            source=source,
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )
        return self

    @function
    def scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "registry",
        severity_cutoff: (
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
        output_format: Annotated[str | None, Doc("Report output formatter")] = "sarif",
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

        if severity_cutoff:
            cmd.extend(["--fail-on", severity_cutoff])

        container: dagger.Container = self.container()
        container = container.with_exec(cmd, use_entrypoint=True, expect=expect)
        return container.file(output_file)

    @function
    def with_scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "registry",
        severity_cutoff: (
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
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan container image (for chaining)"""
        self.scan_image(
            source=source,
            source_type=source_type,
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )
        return self

    @function
    def scan_directory(
        self,
        source: Annotated[dagger.Directory, Doc("Directory to scan")],
        source_type: Annotated[str | None, Doc("Source type")] | None = "dir",
        severity_cutoff: (
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
        output_format: Annotated[str | None, Doc("Report output formatter")] = "sarif",
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

        if severity_cutoff:
            cmd.extend(["--fail-on", severity_cutoff])

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
        severity_cutoff: (
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
        output_format: Annotated[str | None, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan dir (for chaining)"""
        self.scan_directory(
            source=source,
            source_type=source_type,
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )
        return self

    @function
    def scan_file(
        self,
        source: Annotated[dagger.File, Doc("File to scan")],
        source_type: Annotated[str | None, Doc("Source type")] = "file",
        severity_cutoff: (
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
        output_format: Annotated[str | None, Doc("Report output formatter")] = "sarif",
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

        if severity_cutoff:
            cmd.extend(["--fail-on", severity_cutoff])

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
        severity_cutoff: (
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
        output_format: Annotated[str | None, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan file (for chaining)"""
        self.scan_file(
            source=source,
            source_type=source_type,
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )
        return self
