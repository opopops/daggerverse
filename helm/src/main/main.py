from typing import Annotated, Self
from urllib.parse import urlparse

import dagger
from dagger import Doc, Name, dag, function, object_type

import yaml


@object_type
class Helm:
    """Helm"""

    image: str
    version: str
    user: str
    chart: dagger.File | None
    docker_config: dagger.File | None
    container_: dagger.Container | None

    @classmethod
    async def create(
        cls,
        image: Annotated[str, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str, Doc("Helm version")] = "latest",
        user: Annotated[str, Doc("Image user")] = "65532",
        chart: Annotated[dagger.File | None, Doc("The chart archive")] = None,
        docker_config: Annotated[dagger.File | None, Doc("Docker config file")] = None,
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
            chart=chart,
            docker_config=docker_config,
            container_=None,
        )

    def helm_registry_config(self) -> dagger.File:
        """Returns the docker config file"""
        return self.container_.file("$HELM_REGISTRY_CONFIG", expand=True)

    @function
    def container(self) -> dagger.Container:
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        pkg = "helm"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "kubectl", pkg])
            .with_entrypoint(["/usr/bin/helm"])
            .with_user(self.user)
            .with_env_variable("HELM_CACHE_HOME", "/tmp/helm/cache", expand=True)
            .with_env_variable("HELM_CONFIG_HOME", "/tmp/helm/config", expand=True)
            .with_env_variable("HELM_DATA_HOME", "/tmp/helm/data", expand=True)
            .with_env_variable(
                "HELM_REGISTRY_CONFIG",
                "${HELM_CONFIG_HOME}/registry/config.json",
                expand=True,
            )
            .with_exec(
                [
                    "mkdir",
                    "-p",
                    "$HELM_CACHE_HOME",
                    "$HELM_CONFIG_HOME",
                    "$HELM_CONFIG_HOME/registry",
                    "$HELM_DATA_HOME",
                ],
                use_entrypoint=False,
                expand=True,
            )
            .with_new_file(
                "$HELM_REGISTRY_CONFIG",
                contents="",
                owner=self.user,
                permissions=0o600,
                expand=True,
            )
        )

        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        container: dagger.Container = self.container()
        cmd = [
            "sh",
            "-c",
            (
                f"helm registry login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.container_ = container.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

    def get_registry_address(self, url: str) -> str:
        """Retrieves the registry address from the given url"""
        url_parsed = None
        if url.startswith("oci://"):
            url_parsed = urlparse(url)
        else:
            url_parsed = urlparse(f"//{url}")
        return "/".join([url_parsed.netloc, url_parsed.path.lstrip("/")])

    @function
    async def lint(
        self,
        source: Annotated[dagger.Directory, Doc("Chart directory")],
        strict: Annotated[bool, Doc("Fail on lint warnings")] = False,
        quiet: Annotated[bool, Doc("Print only warnings and errors")] = False,
    ) -> str:
        """Verify that the chart is well-formed"""
        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART_PATH", "/tmp/chart")
            .with_directory("$HELM_CHART_PATH", source, expand=True)
            .with_workdir("$HELM_CHART_PATH", expand=True)
        )

        cmd = ["lint", "."]
        if strict:
            cmd.extend(["--strict"])
        if quiet:
            cmd.extend(["--quiet"])

        return await container.with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def with_lint(
        self,
        source: Annotated[dagger.Directory, Doc("Chart directory")],
        strict: Annotated[bool, Doc("Fail on lint warnings")] = False,
        quiet: Annotated[bool, Doc("Print only warnings and errors")] = False,
    ) -> Self:
        """Verify that the chart is well-formed (for chaining)"""
        await self.lint(source=source, strict=strict, quiet=quiet)
        return self

    @function
    async def template(
        self,
        source: Annotated[dagger.Directory, Doc("Chart directory")],
        show_only: Annotated[
            list[str] | None,
            Doc("Only show manifests rendered from the given templates"),
        ] = None,
        sets: Annotated[
            list[str] | None, Doc("Set values on the command"), Name("set")
        ] = None,
        set_files: Annotated[
            list[str] | None,
            Doc("Set values from respective files specified via the command"),
            Name("set_file"),
        ] = None,
        set_jsons: Annotated[
            list[dagger.File] | None,
            Doc("Set JSON values on the command"),
            Name("set_json"),
        ] = None,
        set_literals: Annotated[
            list[dagger.File] | None,
            Doc("Set a literal STRING value on the command"),
            Name("set_literal"),
        ] = None,
        set_strings: Annotated[
            list[dagger.File] | None,
            Doc("Set STRING values on the command line"),
            Name("set_string"),
        ] = None,
    ) -> str:
        """Render chart templates locally and display the output"""
        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART_PATH", "/tmp/chart")
            .with_directory("$HELM_CHART_PATH", source, expand=True)
            .with_workdir("$HELM_CHART_PATH", expand=True)
        )

        cmd = ["template", "."]
        if show_only:
            cmd.extend(["--set", ",".join(show_only)])
        if sets:
            cmd.extend(["--set", ",".join(sets)])
        if set_files:
            cmd.extend(["--set-file", ",".join(set_files)])
        if set_jsons:
            cmd.extend(["--set-json", ",".join(set_jsons)])
        if set_literals:
            cmd.extend(["--set-literal", ",".join(set_literals)])
        if set_strings:
            cmd.extend(["--set-string", ",".join(set_strings)])

        return await container.with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def package(
        self,
        source: Annotated[dagger.Directory, Doc("Chart directory")],
        app_version: Annotated[
            str, Doc("Set the appVersion on the chart to this version")
        ] = "",
        version: Annotated[
            str, Doc("Set the version on the chart to this semver version")
        ] = "",
        dependency_update: Annotated[bool, Doc("Update dependencies")] = False,
    ) -> dagger.File:
        """Packages a chart into a versioned chart archive file"""
        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART_PATH", "/tmp/chart")
            .with_env_variable("HELM_CHART_DEST_PATH", "/tmp/dest")
            .with_directory("$HELM_CHART_PATH", source, owner=self.user, expand=True)
            .with_workdir("$HELM_CHART_PATH", expand=True)
        )

        cmd = ["package", ".", "--destination", "$HELM_CHART_DEST_PATH"]
        if app_version:
            cmd.extend(["--app-version", app_version])
        if version:
            cmd.extend(["--version", version])
        if dependency_update:
            cmd.extend(["--dependency-update"])

        dest_dir: dagger.Directory = await container.with_exec(
            cmd, use_entrypoint=True, expand=True
        ).directory("$HELM_CHART_DEST_PATH", expand=True)
        dest_files: list[str] = await dest_dir.glob("*.tgz")

        return dest_dir.file(dest_files[0])

    @function
    async def with_package(
        self,
        source: Annotated[dagger.Directory, Doc("Chart directory")],
        app_version: Annotated[
            str, Doc("Set the appVersion on the chart to this version")
        ] = "",
        version: Annotated[
            str, Doc("Set the version on the chart to this semver version")
        ] = "",
        dependency_update: Annotated[bool, Doc("Update dependencies")] = False,
    ) -> Self:
        """Packages a chart into a versioned chart archive file (for chaining)"""
        self.chart = await self.package(
            source=source,
            app_version=app_version,
            version=version,
            dependency_update=dependency_update,
        )
        return self

    @function
    async def push(
        self,
        registry: Annotated[str, Doc("Registry host")],
        chart: Annotated[dagger.File | None, Doc("Chart archive")] = None,
        username: Annotated[str, Doc("Registry username")] = "",
        password: Annotated[dagger.Secret | None, Doc("Registry password")] = None,
        plain_http: Annotated[
            bool, Doc("Use insecure HTTP connections for the chart upload")
        ] = False,
    ) -> str:
        """Verify that the chart is well-formed"""
        registry_address: str = self.get_registry_address(registry)

        if username and password:
            self.with_registry_auth(
                username=username,
                secret=password,
                address=registry_address,
            )

        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART", "/tmp/chart.tgz")
            .with_file("$HELM_CHART", chart or self.chart, owner=self.user, expand=True)
        )

        cmd = ["show", "chart", "$HELM_CHART"]
        info = yaml.safe_load(
            await container.with_exec(cmd, use_entrypoint=True, expand=True).stdout()
        )

        cmd = ["push", "$HELM_CHART", f"oci://{registry_address}"]
        if plain_http:
            cmd.extend(["--plain-http"])

        await container.with_exec(cmd, use_entrypoint=True, expand=True).stdout()
        image: str = f"{registry_address}/{info.get('name')}:{info.get('version')}"
        digest: str = await dag.crane(docker_config=self.helm_registry_config()).digest(
            image
        )
        return f"{image}@{digest}"

    @function
    async def package_push(
        self,
        source: Annotated[dagger.Directory, Doc("Chart directory")],
        registry: Annotated[str, Doc("Registry host")],
        username: Annotated[str, Doc("Registry username")] = "",
        password: Annotated[dagger.Secret | None, Doc("Registry password")] = None,
        plain_http: Annotated[
            bool, Doc("Use insecure HTTP connections for the chart upload")
        ] = False,
        app_version: Annotated[
            str, Doc("Set the appVersion on the chart to this version")
        ] = "",
        version: Annotated[
            str, Doc("Set the version on the chart to this semver version")
        ] = "",
        dependency_update: Annotated[bool, Doc("Update dependencies")] = False,
    ) -> str:
        """Packages a chart an push it to the registry"""

        chart: dagger.File = await self.package(
            source=source,
            app_version=app_version,
            version=version,
            dependency_update=dependency_update,
        )

        return await self.push(
            chart=chart,
            registry=registry,
            username=username,
            password=password,
            plain_http=plain_http,
        )
