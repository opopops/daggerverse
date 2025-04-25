from typing import Annotated, Self
import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Grype:
    """Grype CLI"""

    image: Annotated[str, Doc("Grype image")] = field(
        default="cgr.dev/chainguard/wolfi-base:latest"
    )
    version: Annotated[str, Doc("Grype version")] | None = field(default=None)
    user: Annotated[str, Doc("Image user")] = field(default="nonroot")

    docker_config: Annotated[dagger.File, Doc("Docker config file")] | None = field(
        default=None
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )

    container_: dagger.Container | None = None

    @function
    def container(self) -> dagger.Container:
        """Returns configured grype container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()

        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )

        pkg = "grype"
        if self.version:
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_env_variable("GRYPE_DB_CACHE_DIR", "/tmp/cache")
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "docker-cli", pkg])
            .with_entrypoint(["/usr/bin/grype"])
            .with_user(self.user)
            .with_mounted_cache(
                "$GRYPE_DB_CACHE_DIR",
                dag.cache_volume("grype-db-cache"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=self.user,
                expand=True,
            )
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
        address: Annotated[str, Doc("Registry host")] | None = "docker.io",
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
    def scan(
        self,
        source: Annotated[str, Doc("Source to scan")],
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan"""
        output_file = f"/tmp/report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [source, "--output", output_format, "--file", output_file]

        if severity_cutoff:
            cmd.extend(["--fail-on", severity_cutoff])

        container: dagger.Container = self.container()
        container = container.with_exec(
            cmd, use_entrypoint=True, expand=True, expect=expect
        )
        return container.file(output_file)

    @function
    def with_scan(
        self,
        source: Annotated[str, Doc("Source to scan")],
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
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
        source_type: Annotated[str, Doc("Source type")] | None = "registry",
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan container image"""
        output_file = f"/tmp/report.{output_format}"
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
        container = container.with_exec(
            cmd, use_entrypoint=True, expand=True, expect=expect
        )
        return container.file(output_file)

    @function
    def with_scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        source_type: Annotated[str, Doc("Source type")] | None = "registry",
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
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
        source_type: Annotated[str, Doc("Source type")] | None = "dir",
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan directory"""
        output_file = f"/tmp/report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [
            f"{source_type}:$GRYPE_DIR_TO_SCAN",
            "--output",
            output_format,
            "--file",
            output_file,
        ]

        if severity_cutoff:
            cmd.extend(["--fail-on", severity_cutoff])

        container: dagger.Container = (
            self.container()
            .with_env_variable("GRYPE_DIR_TO_SCAN", "/grype")
            .with_directory(
                path="$GRYPE_DIR_TO_SCAN",
                directory=source,
                owner=self.user,
                expand=True,
            )
            .with_exec(cmd, use_entrypoint=True, expand=True, expect=expect)
        )
        return container.file(output_file)

    @function
    def with_scan_directory(
        self,
        source: Annotated[dagger.Directory, Doc("Directory to scan")],
        source_type: Annotated[str, Doc("Source type")] | None = "registry",
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
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
        source_type: Annotated[str, Doc("Source type")] | None = "file",
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan file"""
        output_file = f"/tmp/report.{output_format}"
        expect = dagger.ReturnType.SUCCESS
        if not fail:
            expect = dagger.ReturnType.ANY

        cmd = [
            f"{source_type}:$GRYPE_FILE_TO_SCAN",
            "--output",
            output_format,
            "--file",
            output_file,
        ]

        if severity_cutoff:
            cmd.extend(["--fail-on", severity_cutoff])

        container: dagger.Container = (
            self.container()
            .with_env_variable("GRYPE_FILE_TO_SCAN", "/grype.file")
            .with_file(
                path="$GRYPE_FILE_TO_SCAN", source=source, owner=self.user, expand=True
            )
            .with_exec(cmd, use_entrypoint=True, expand=True, expect=expect)
        )
        return container.file(output_file)

    @function
    def with_scan_file(
        self,
        source: Annotated[dagger.File, Doc("File to scan")],
        source_type: Annotated[str, Doc("Source type")] | None = "registry",
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
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
