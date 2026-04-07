use super::*;

impl<I: InterfaceFeuApplication> FeuApplication<I> {
    /// Affiche la version de `feu-noyau` via l'interface.
    pub fn affiche_version() {
        println!(
            "{} version {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
    }
}
