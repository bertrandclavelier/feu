//! Interface textuelle de Feu.
//!
//! Un carré centré dans le terminal accueille toute l'interaction. La saisie
//! se fait sur une ligne d'invite positionnée au centre vertical du carré.
//! La boucle principale tourne en continu : dessin → événement → mise à jour
//! de l'état → retour au dessin.

use std::io::Error;

use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Block;
use ratatui::{DefaultTerminal, Frame};

/// État courant de l'interface entre deux frames.
struct EtatTui {
    quitter: bool,
    _saisie: String,
}

impl EtatTui {
    fn new() -> Self {
        Self {
            quitter: false,
            _saisie: String::new(),
        }
    }
}

/// Orchestre la boucle principale et le rendu.
struct Tui {
    etat_tui: EtatTui,
}

impl Tui {
    fn new() -> Self {
        Self {
            etat_tui: EtatTui::new(),
        }
    }

    /// Boucle principale : dessine, attend un événement, met à jour l'état.
    fn lancer(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        loop {
            terminal.draw(|frame| self.dessiner(frame))?;
            if crossterm::event::read()?.is_key_press() {
                self.etat_tui.quitter = true;
            }

            if self.etat_tui.quitter {
                break;
            }
        }
        Ok(())
    }

    fn dessiner(&self, frame: &mut Frame) {
        // Carré centré : 62×31 pour compenser le ratio largeur/hauteur des cellules terminal.
        let vertical = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(31),
            Constraint::Fill(1),
        ])
        .split(frame.area());

        let horizontal = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Length(62),
            Constraint::Fill(1),
        ])
        .split(vertical[1]);

        frame.render_widget(Block::bordered(), horizontal[1]);

        // Découpage à l'intérieur de la bordure pour ne pas l'écraser.
        let carre = horizontal[1].inner(Margin {
            horizontal: 1,
            vertical: 1,
        });

        let carre_decoupage_vertical = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .split(carre);

        let invite = Line::from(vec![
            Span::raw("feu "),
            Span::styled(
                "›",
                Style::default().fg(ratatui::style::Color::Rgb(255, 90, 31)),
            ),
        ]);

        // Marge horizontale pour positionner l'invite visuellement au centre du carré.
        let zone_invite = carre_decoupage_vertical[1].inner(Margin {
            horizontal: 10,
            vertical: 0,
        });
        frame.render_widget(invite, zone_invite);
    }
}

fn main() -> Result<(), Error> {
    let mut tui = Tui::new();
    ratatui::run(|terminal| tui.lancer(terminal))?;
    Ok(())
}
