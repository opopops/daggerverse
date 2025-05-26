from typing import Annotated, Self

import dagger
from dagger import Doc, dag, function, object_type


@object_type
class Crane:
    """Crane module"""

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
        version: Annotated[str | None, Doc("Crane version")] = "latest",
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
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()

        pkg = "crane"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", pkg])
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_user(self.user)
            .with_exec(["mkdir", "-p", "$DOCKER_CONFIG"], expand=True)
            .with_new_file(
                "${DOCKER_CONFIG}/config.json",
                contents="",
                owner=self.user,
                permissions=0o600,
                expand=True,
            )
            .with_workdir("/crane")
            .with_entrypoint(["/usr/bin/crane"])
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
    def manifest(
        self,
        image: Annotated[str, Doc("Image")],
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
    ) -> dagger.File:
        """Returns the manifest file of an image"""
        container: dagger.Container = self.container()
        cmd = ["manifest", image]

        if platform:
            cmd.extend(["--platform", platform])

        return container.with_exec(
            cmd, redirect_stdout="/tmp/stdout", use_entrypoint=True
        ).file("/tmp/stdout")

    @function
    async def digest(
        self,
        image: Annotated[str, Doc("Image")],
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
        full_ref: Annotated[
            bool | None, Doc("Print the full image reference by digest")
        ] = False,
        tarball: Annotated[
            dagger.File | None, Doc("Tarball containing the image")
        ] = None,
    ) -> str:
        """Tag remote image without downloading it."""
        container: dagger.Container = self.container()
        cmd = ["digest", image]

        if platform:
            cmd.extend(["--platform", platform])

        if full_ref:
            cmd.extend(["--full-ref"])

        if tarball:
            path = "/tmp/image.tar"
            container.with_mounted_file(path=path, source=tarball, owner=self.user)
            cmd.extend(["--tarball", path])

        digest: str = await container.with_exec(cmd, use_entrypoint=True).stdout()
        return digest.strip()

    @function
    async def copy(
        self,
        source: Annotated[str, Doc("Source image")],
        target: Annotated[str, Doc("Target image")],
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
        jobs: Annotated[
            int | None, Doc("The maximum number of concurrent copies")
        ] = None,
        all_tags: Annotated[bool | None, Doc("Copy all tags from SRC to DST")] = False,
        no_clobber: Annotated[
            bool | None, Doc("Avoid overwriting existing tags in DST")
        ] = False,
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

        digest: str = (
            await self.container().with_exec(cmd, use_entrypoint=True).stdout()
        )
        return digest.strip()

    @function
    async def with_copy(
        self,
        source: Annotated[str, Doc("Source image")],
        target: Annotated[str, Doc("Target image")],
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
        jobs: Annotated[int, Doc("The maximum number of concurrent copies")]
        | None = None,
        all_tags: Annotated[bool | None, Doc("Copy all tags from SRC to DST")] = False,
        no_clobber: Annotated[
            bool | None, Doc("Avoid overwriting existing tags in DST")
        ] = False,
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
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
    ) -> str:
        """Tag remote image without downloading it."""
        cmd = ["tag", image, tag]

        if platform:
            cmd.extend(["--platform", platform])

        digest: str = (
            await self.container().with_exec(cmd, use_entrypoint=True).stdout()
        )
        return digest.strip()

    @function
    async def with_tag(
        self,
        image: Annotated[str, Doc("Image")],
        tag: Annotated[str, Doc("New tag")],
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
    ) -> Self:
        """Tag remote image without downloading it (For chaining)."""
        await self.tag(image=image, tag=tag, platform=platform)
        return self

    @function
    async def push(
        self,
        path: Annotated[dagger.Directory, Doc("OCI layout dir")],
        image: Annotated[str, Doc("Image tag")],
        index: Annotated[
            bool | None, Doc("Push a collection of images as a single index")
        ] = False,
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
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
        index: Annotated[
            bool | None, Doc("Push a collection of images as a single index")
        ] = False,
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
    ) -> Self:
        """Push image from OCI layout dir (For chaining)"""
        await self.push(path=path, image=image, index=index, platform=platform)
        return self

    @function
    async def push_tarball(
        self,
        tarball: Annotated[dagger.File, Doc("Image tarball")],
        image: Annotated[str, Doc("Image tag")],
        index: Annotated[
            bool | None, Doc("Push a collection of images as a single index")
        ] = False,
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
    ) -> str:
        """Push image from tarball"""
        cmd = ["push", "$IMAGE_TARBALL", image]

        if index:
            cmd.extend(["--index"])
        if platform:
            cmd.extend(["--platform", platform])

        container = (
            self.container()
            .with_env_variable("IMAGE_TARBALL", "/tmp/image.tar")
            .with_file("$IMAGE_TARBALL", tarball, owner=self.user, expand=True)
            .with_exec(cmd, use_entrypoint=True, expand=True)
        )

        return await container.stdout()

    @function
    async def with_push_tarball(
        self,
        tarball: Annotated[dagger.File, Doc("Image tarball")],
        image: Annotated[str, Doc("Image tag")],
        platform: Annotated[
            dagger.Platform | None, Doc("Specifies the platform")
        ] = None,
    ) -> Self:
        """Push image from tarball (For chaining)"""
        await self.push_tarball(tarball=tarball, image=image, platform=platform)
        return self
