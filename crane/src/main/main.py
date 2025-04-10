from typing import Annotated, Self

import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Crane:
    """Crane module"""

    image: Annotated[str, Doc("Crane image")] = field(
        default="cgr.dev/chainguard/wolfi-base:latest"
    )
    version: Annotated[str, Doc("Crane version")] | None = field(default=None)

    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("image user")] | None = field(default="65532")

    container_: dagger.Container | None = None

    @function
    def container(self) -> dagger.Container:
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )

        pkg = "crane"
        if self.version:
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", pkg])
            .with_entrypoint(["/usr/bin/crane"])
            .with_user(self.user)
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
                f"crane auth login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.container_ = container.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

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
    async def copy(
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
        """Copy images."""
        cmd = ["copy", source, target]

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
    async def with_copy(
        self,
        source: Annotated[str, Doc("Source image")],
        target: Annotated[str, Doc("Target image")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
        jobs: Annotated[int, Doc("The maximum number of concurrent copies")]
        | None = None,
        all_tags: Annotated[bool, Doc("Copy all tags from SRC to DST")] | None = False,
        no_clobber: Annotated[bool, Doc("Avoid overwriting existing tags in DST")]
        | None = False,
    ) -> Self:
        """Copy images (For chaining)."""
        await self.copy(
            source=source,
            target=target,
            platform=platform,
            jobs=jobs,
            all_tags=all_tags,
            no_clobber=no_clobber,
        )
        return self

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

    @function
    async def with_tag(
        self,
        image: Annotated[str, Doc("Image")],
        tag: Annotated[str, Doc("New tag")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> Self:
        """Tag remote image without downloading it (For chaining)."""
        await self.tag(
            image=image,
            tag=tag,
            platform=platform,
        )
        return self

    @function
    async def push(
        self,
        path: Annotated[dagger.Directory, Doc("OCI layout dir")],
        image: Annotated[str, Doc("Image tag")],
        index: Annotated[bool, Doc("Push a collection of images as a single index")]
        | None = None,
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> str:
        """Push image from OCI layout dir"""
        cmd = ["push", "$IMAGE_PATH", image]

        if index:
            cmd.extend(["--index"])
        if platform:
            cmd.extend(["--platform", platform])

        container = (
            self.container()
            .with_env_variable("IMAGE_PATH", "/crane/image")
            .with_directory("$IMAGE_PATH", path, expand=True)
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )

        return await container.stdout()

    @function
    async def with_push(
        self,
        path: Annotated[dagger.Directory, Doc("OCI layout dir")],
        image: Annotated[str, Doc("Image tag")],
        index: Annotated[bool, Doc("Push a collection of images as a single index")]
        | None = None,
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> Self:
        """Push image from OCI layout dir (For chaining)"""
        await self.push(
            path=path,
            image=image,
            index=index,
            platform=platform,
        )
        return self

    @function
    async def push_tarball(
        self,
        tarball: Annotated[dagger.File, Doc("Image tarball")],
        image: Annotated[str, Doc("Image tag")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> str:
        """Push image from tarball"""
        cmd = ["push", "$IMAGE_TARBALL", image]

        if platform:
            cmd.extend(["--platform", platform])

        container = (
            self.container()
            .with_env_variable("IMAGE_TARBALL", "/tmp/image.tar")
            .with_file("$IMAGE_TARBALL", tarball, expand=True)
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )

        return await container.stdout()

    @function
    async def with_push_tarball(
        self,
        tarball: Annotated[dagger.File, Doc("Image tarball")],
        image: Annotated[str, Doc("Image tag")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> Self:
        """Push image from tarball (For chaining)"""
        await self.push_tarball(
            tarball=tarball,
            image=image,
            platform=platform,
        )
        return self
