//
// The constants exported from this module are generated from
// binarly-platform-schemas/meta/properties.yml.
//
// To add a new property type, add the property to that repository, and sync. the submodule on this
// repository.
//
include!(concat!(env!("OUT_DIR"), "/properties.generated.rs"));
