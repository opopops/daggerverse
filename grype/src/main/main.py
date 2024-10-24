from typing import Annotated
import os
import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Grype:
    """Grype CLI"""

    image: Annotated[str, Doc("Grype image")] = field(
        default="cgr.dev/chainguard/grype:latest"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("Image user")] = field(default="nonroot")

    def container_(self) -> dagger.Container:
        """Returns grype container"""
        container: dagger.Container = dag.container()
        cache_dir: str = "/tmp/.grype/cache"

        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )
        return (
            container.from_(address=self.image)
            .with_user(self.user)
            .with_env_variable("GRYPE_DB_CACHE_DIR", cache_dir)
            .with_mounted_cache(
                cache_dir,
                dag.cache_volume("GRYPE_DB_CACHE"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=self.user,
            )
        )

    @function
    async def scan_image(
        self,
        source: Annotated[str, Doc("Image to scan")],
        scheme: Annotated[str, Doc("Source scheme")] | None = "docker",
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

        return await self.container_().with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def scan_dir(
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

        return await (
            self.container_()
            .with_env_variable("GRYPE_DIR_TO_SCAN", "/grype")
            .with_directory(
                path="$GRYPE_DIR_TO_SCAN", directory=source, owner=self.user, expand=True
            )
            .with_exec(cmd, use_entrypoint=True, expand=True)
            .stdout()
        )

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

        return await (
            self.container_()
            .with_env_variable("GRYPE_FILE_TO_SCAN", "/grype/file_to_scan")
            .with_file(
                path="$GRYPE_FILE_TO_SCAN", source=source, owner=self.user, expand=True
            )
            .with_exec(cmd, use_entrypoint=True, expand=True)
            .stdout()
        )
