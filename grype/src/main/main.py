from typing import Annotated, Self
import os
import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Grype:
    """Grype CLI"""

    image: Annotated[str, Doc("Grype image")] = field(
        default="cgr.dev/chainguard/wolfi-base:latest"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("Image user")] = field(default="nonroot")

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
        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "grype", "docker-cli"])
            .with_entrypoint(["/usr/bin/grype"])
            .with_user(self.user)
            .with_env_variable("GRYPE_DB_CACHE_DIR", "/tmp/cache")
            .with_mounted_cache(
                "$GRYPE_DB_CACHE_DIR",
                dag.cache_volume("GRYPE_DB_CACHE"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=self.user,
                expand=True,
            )
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
    async def scan(
        self,
        source: Annotated[str, Doc("Source to scan")],
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> str:
        """Scan"""
        cmd = [source, "--output", output_format]

        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        container: dagger.Container = self.container()
        container = container.with_exec(cmd, use_entrypoint=True, expand=True)
        return await container.stdout()

    @function
    async def with_scan(
        self,
        source: Annotated[str, Doc("Source to scan")],
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan (for chaining)"""
        await self.scan(source=source, fail_on=fail_on, output_format=output_format)
        return self

    @function
    async def scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        scheme: Annotated[str, Doc("Source scheme")] | None = "registry",
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> str:
        """Scan container image"""
        cmd = [f"{scheme}:{source}", "--output", output_format]

        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        container: dagger.Container = self.container()
        container = container.with_exec(cmd, use_entrypoint=True, expand=True)
        return await container.stdout()

    @function
    async def with_scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        scheme: Annotated[str, Doc("Source scheme")] | None = "registry",
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan container image (for chaining)"""
        await self.scan_image(
            source=source, scheme=scheme, fail_on=fail_on, output_format=output_format
        )
        return self

    @function
    async def scan_directory(
        self,
        source: Annotated[dagger.Directory, Doc("Directory to scan")],
        scheme: Annotated[str, Doc("Source scheme")] | None = "dir",
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> str:
        """Scan directory"""
        cmd = [f"{scheme}:$GRYPE_DIR_TO_SCAN", "--output", output_format]

        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        container: dagger.Container = (
            await self.container()
            .with_env_variable("GRYPE_DIR_TO_SCAN", "/grype")
            .with_directory(
                path="$GRYPE_DIR_TO_SCAN",
                directory=source,
                owner=self.user,
                expand=True,
            )
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )
        return await container.stdout()

    @function
    async def with_scan_directory(
        self,
        source: Annotated[dagger.Directory, Doc("Directory to scan")],
        scheme: Annotated[str, Doc("Source scheme")] | None = "registry",
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan dir (for chaining)"""
        await self.scan_dir(
            source=source, scheme=scheme, fail_on=fail_on, output_format=output_format
        )
        return self

    @function
    async def scan_file(
        self,
        source: Annotated[dagger.File, Doc("File to scan")],
        scheme: Annotated[str, Doc("Source scheme")] | None = "file",
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> str:
        """Scan file"""

        cmd = [f"{scheme}:$GRYPE_FILE_TO_SCAN", "--output", output_format]

        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        container: dagger.Container = (
            await self.container()
            .with_env_variable("GRYPE_FILE_TO_SCAN", "/grype.file")
            .with_file(
                path="$GRYPE_FILE_TO_SCAN", source=source, owner=self.user, expand=True
            )
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )
        return await container.stdout()

    @function
    async def with_scan_file(
        self,
        source: Annotated[dagger.File, Doc("File to scan")],
        scheme: Annotated[str, Doc("Source scheme")] | None = "registry",
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan file (for chaining)"""
        await self.scan_file(
            source=source, scheme=scheme, fail_on=fail_on, output_format=output_format
        )
        return self
