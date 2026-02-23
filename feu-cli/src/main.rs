use feu_core::Feu;
mod interface_cli;
use interface_cli::InterfaceCli;

fn main() {
    let interface_cli = InterfaceCli::new();

    let _feu = Feu::new(interface_cli);
}
