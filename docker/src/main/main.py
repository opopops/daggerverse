import asyncio
from typing import Annotated, Self

import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

from .build import Build


@object_type
class Docker:
    """Docker"""

    container_: dagger.Container | None = None

    def container(self, platform: dagger.Platform | None = None) -> dagger.Container:
        """Returns authentcated container"""
        if self.container_:
            return self.container_
        self.container_ = dag.container(platform=platform)
        return self.container_

    @function
    async def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        self.container_ = self.container().with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    async def build(
        self,
        context: Annotated[dagger.Directory, DefaultPath("."), Doc("Context")],
        dockerfile: Annotated[
            dagger.File, Doc("Location of the Dockerfile"), Name("file")
        ],
        target: Annotated[str, Doc("Set the target build stage to build")] = "",
        build_args: Annotated[
            list[str],
            Doc("Build args to pass to the build in the format of name=value"),
            Name("build_arg"),
        ] = (),
        secrets: Annotated[
            list[dagger.Secret], Doc("Secrets to pass to the build"), Name("secret")
        ] = (),
        platforms: Annotated[
            list[dagger.Platform],
            Doc("Set target platform for build"),
            Name("platform"),
        ] = (),
    ) -> Build:
        """Build multi-arch OCI image"""
        platform_variants: list[dagger.Container] = []
        dagger_build_args: list[dagger.BuildArg] = []

        # get build context with dockerfile added
        workspace = (
            dag.container()
            .with_directory("/src", context)
            .with_workdir("/src")
            .with_file("/src/dagger.Dockerfile", dockerfile)
            .directory("/src")
        )

        async def build_(
            container: dagger.Container,
            context: dagger.Directory,
            dockerfile: str,
            target: str,
            build_args: list[dagger.BuildArg],
            secrets: list[dagger.Secret],
        ):
            container = await container.build(
                context=context,
                dockerfile=dockerfile,
                target=target,
                build_args=build_args,
                secrets=secrets,
            )
            platform_variants.append(container)

        for build_arg in build_args:
            build_arg_split = build_arg.split("=")
            dagger_build_args.append(
                dagger.BuildArg(name=build_arg_split[0], value=build_arg_split[1])
            )

        if platforms:
            async with asyncio.TaskGroup() as tg:
                for platform in platforms:
                    tg.create_task(
                        build_(
                            container=dag.container(platform=platform),
                            context=workspace,
                            dockerfile="dagger.Dockerfile",
                            target=target,
                            build_args=dagger_build_args,
                            secrets=secrets,
                        )
                    )
        else:
            platform_variants.append(
                self.container().build(
                    context=workspace,
                    dockerfile="dagger.Dockerfile",
                    target=target,
                    build_args=dagger_build_args,
                    secrets=secrets,
                )
            )
        return Build(platform_variants=platform_variants, container_=self.container())
