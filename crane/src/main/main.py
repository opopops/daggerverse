from typing import Annotated

import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Crane:
    """Crane module"""

    image: Annotated[str, Doc("Crane image")] = field(
        default="cgr.dev/chainguard/crane:latest"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("Cosign image user")] = field(default="nonroot")

    def container(self) -> dagger.Container:
        """Returns Cosign container"""
        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )
        return container.from_(address=self.image).with_user(self.user)

    @function
    async def manifest(
        self,
        image: Annotated[str, Doc("Image")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> str:
        """Get the manifest of an image"""
        container: dagger.Container = self.container()
        cmd = ["manifest", image]

        if platform:
            cmd.extend(["--platform", platform])

        return await container.with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def digest(
        self,
        image: Annotated[str, Doc("Image")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
        full_ref: Annotated[bool, Doc("Print the full image reference by digest")]
        | None = False,
        tarball: Annotated[str, Doc("Path to tarball containing the image")]
        | None = None,
    ) -> str:
        """Tag remote image without downloading it."""
        container: dagger.Container = self.container()
        cmd = ["digest", image]

        if platform:
            cmd.extend(["--platform", platform])

        if full_ref:
            cmd.extend(["--full-ref"])

        if tarball:
            path = f"/tmp/{tarball}"
            container.with_mounted_file(path=path, source=tarball, owner=self.user)
            cmd.extend(["--tarball", path])

        return await container.with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def cp(
        self,
        source: Annotated[str, Doc("Source image")],
        target: Annotated[str, Doc("Target image")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
        jobs: Annotated[int, Doc("The maximum number of concurrent copies")]
        | None = None,
        all_tags: Annotated[bool, Doc("Copy all tags from SRC to DST")] | None = False,
        no_clobber: Annotated[bool, Doc("Avoid overwriting existing tags in DST")]
        | None = False,
    ) -> str:
        """Tag remote image without downloading it."""
        cmd = ["cp", source, target]

        if platform:
            cmd.extend(["--platform", platform])

        if jobs:
            cmd.extend(["--jobs", jobs])

        if all_tags:
            cmd.extend(["--all-tags"])

        if no_clobber:
            cmd.extend(["--no-clobber"])

        return await self.container().with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def tag(
        self,
        image: Annotated[str, Doc("Image")],
        tag: Annotated[str, Doc("New tag")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> str:
        """Tag remote image without downloading it."""
        cmd = ["tag", image, tag]

        if platform:
            cmd.extend(["--platform", platform])

        return await self.container().with_exec(cmd, use_entrypoint=True).stdout()
