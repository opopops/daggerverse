from typing import Annotated

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
    async def scan(
        self,
        image: Annotated[str, Doc("Image to scan")],
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
        cmd = [image, "--output", output_format]

        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        return await self.container_().with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def scan_tarball(
        self,
        tarball: Annotated[dagger.File, Doc("Tarball to scan")],
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
        """Scan tarball"""
        tar_file = "/tmp/image.tar"
        cmd = [tar_file, "--output", output_format]

        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        return await (
            self.container_()
            .with_file(path=tar_file, source=tarball, owner=self.user)
            .with_exec(cmd, use_entrypoint=True)
            .stdout()
        )
