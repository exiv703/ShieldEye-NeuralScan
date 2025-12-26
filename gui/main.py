import sys
import os
import gi

gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, Gdk, Gio

from gui.window import MainWindow

class NeuralScanApp(Gtk.Application):
    def __init__(self):
        super().__init__(
            application_id='com.shieldeye.neuralscan',
            flags=Gio.ApplicationFlags.FLAGS_NONE
        )
        self.window = None

    def do_activate(self):
        if not self.window:
            self.window = MainWindow(application=self)
            self._load_css()
        
        self.window.present()

    def _load_css(self):
        css_provider = Gtk.CssProvider()
        css_path = os.path.join(os.path.dirname(__file__), 'style.css')
        
        try:
            css_provider.load_from_path(css_path)
            Gtk.StyleContext.add_provider_for_display(
                Gdk.Display.get_default(),
                css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
        except Exception as e:
            print(f"Failed to load CSS: {e}")

if __name__ == '__main__':
    app = NeuralScanApp()
    exit_status = app.run(sys.argv)
    sys.exit(exit_status)
