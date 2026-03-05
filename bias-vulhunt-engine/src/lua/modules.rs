use std::fs;
use std::path::Path;

pub fn register_default_module_loader(
    context: &mlua::Lua,
    loaders: &mlua::Table,
) -> Result<(), mlua::Error> {
    loaders.set(
        1,
        context.create_function(
            |_lua: &mlua::Lua, module: String| -> Result<mlua::Function, mlua::Error> {
                return Err(mlua::Error::external(format!(
                    "module `{module}` not found; module directory is not accessible",
                )));
            },
        )?,
    )?;

    Ok(())
}

pub fn register_module_loader(
    context: &mlua::Lua,
    module_dir: Option<&Path>,
) -> Result<(), mlua::Error> {
    let package = context.globals().get::<mlua::Table>("package")?;
    let loaders = package.get::<mlua::Table>("loaders")?;

    loaders.clear()?;

    let Some(module_dir) = module_dir else {
        return register_default_module_loader(context, &loaders);
    };

    let module_dir = module_dir.to_path_buf();
    if !module_dir.exists() || !module_dir.is_dir() {
        tracing::debug!(
            "module directory `{}` does not exist or is not a directory; not registering loader",
            module_dir.display()
        );
        return register_default_module_loader(context, &loaders);
    }

    let canonical = module_dir.canonicalize().map_err(|e| {
        mlua::Error::external(format!(
            "failed to canonicalise module directory `{}`: {}",
            module_dir.display(),
            e
        ))
    })?;

    loaders.set(
        1,
        context.create_function(move |lua: &mlua::Lua, module: String| {
            if Path::new(&module).extension().is_some() {
                return Err(mlua::Error::external(format!(
                    "module `{}` must be specified without an extension",
                    module
                )));
            }

            let module_path = canonical.join(&module).with_extension("vhm");

            let canonical_module_path = module_path.canonicalize().map_err(|e| {
                mlua::Error::external(format!(
                    "failed to canonicalise module path `{}`: {}",
                    module_path.display(),
                    e
                ))
            })?;

            if !canonical_module_path.starts_with(&canonical) {
                return Err(mlua::Error::external(format!(
                    "module `{}` is not within the module directory `{}`",
                    module,
                    module_dir.display()
                )));
            }

            if !canonical_module_path.exists() {
                return Err(mlua::Error::external(format!(
                    "module `{}` not found in directory `{}`",
                    module,
                    module_dir.display()
                )));
            }

            let module_content = fs::read_to_string(&module_path).map_err(|e| {
                mlua::Error::external(format!(
                    "failed to read module `{}`: {}",
                    module_path.display(),
                    e
                ))
            })?;

            let chunk = lua.load(&module_content).set_name(&module);

            Ok(chunk.into_function())
        })?,
    )?;

    Ok(())
}
