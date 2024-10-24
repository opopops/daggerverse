from typing import Annotated, Self

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
    user: Annotated[str, Doc("image user")] | None = field(default="nonroot")

    container: Annotated[dagger.Container, Doc("Crane container")] | None = field(
        default=None
    )

    def container_(self) -> dagger.Container:
        """Returns container"""
        if self.container:
            return self.container

        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )
        self.container = container.from_(address=self.image).with_user(self.user)

        return self.container

    @function
    async def with_registry_auth(
        self,
        address: Annotated[str, Doc("Registry host")] | None = "index.docker.io",
        username: Annotated[str, Doc("Registry username")] | None = None,
        secret: Annotated[dagger.Secret, Doc("Registry password")] | None = None,
        docker_config: Annotated[dagger.Directory, Doc("Docker config directory")]
        | None = None,
    ) -> Self:
        """Authenticate with registry"""
        container: dagger.Container = self.container_()
        if docker_config:
            self.container = container.with_env_variable(
                "DOCKER_CONFIG", "/tmp/docker"
            ).with_mounted_directory("/tmp/docker", docker_config, owner=self.user)
        else:
            cmd = [
                "auth",
                "login",
                address,
                "--username",
                username,
                "--password",
                # TODO: use $REGISTRY_PASSWORD instead once dagger is fixed
                await secret.plaintext(),
            ]
            self.container = container.with_secret_variable(
                "REGISTRY_PASSWORD", secret
            ).with_exec(cmd, use_entrypoint=True, expand=True)
        return self

    @function
    async def manifest(
        self,
        image: Annotated[str, Doc("Image")],
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> str:
        """Get the manifest of an image"""
        container: dagger.Container = self.container_()
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
        container: dagger.Container = self.container_()
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

        return await self.container_().with_exec(cmd, use_entrypoint=True).stdout()

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

        return await self.container_().with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def push(
        self,
        path: Annotated[dagger.Directory, Doc("OCI layout dir")],
        image: Annotated[str, Doc("Image tag")],
        index: Annotated[bool, Doc("Push a collection of images as a single index")] | None = None,
        platform: Annotated[str, Doc("Specifies the platform")] | None = None,
    ) -> str:
        """Push image from OCI layout dir"""
        cmd = ["push", "$IMAGE_PATH", image]

        if index:
            cmd.extend(["--index"])
        if platform:
            cmd.extend(["--platform", platform])

        container = (
            self.container_()
            .with_env_variable("IMAGE_PATH", "/crane/image")
            .with_directory("$IMAGE_PATH", path, expand=True)
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )

        return await container.stdout()

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
            self.container_()
            .with_env_variable("IMAGE_TARBALL", "/tmp/image.tar")
            .with_file("$IMAGE_TARBALL", tarball, expand=True)
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )

        return await container.stdout()
