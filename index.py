
from NoUpdates import NoUpdates

# from NoUpdates import NoUpdates
from pystray import Icon, MenuItem, Menu
from PIL import Image


class App:

    def __init__(self) -> None:

        self.nu = NoUpdates()
         # Create menu for the system tray icon
        menu = Menu(
            MenuItem('Open', self._on_open_btn_click),
            MenuItem('Quit', self._quit_action)
        )

        # Create the icon
        img = Image.open(r'imgs/refresh.png')
        img = img.resize((64, 64)) 

        self.icon = Icon('test', img, menu=menu)

        # Run the icon
        self.icon.run()


        
    def _quit_action(self, icon, item):
        self.icon.stop()

        if self.nu.is_app_open():
            self.nu.quit_app()
            self.nu




    def _on_open_btn_click(self, icon, item):

        if not self.nu.is_app_open():
            self.nu.start_app()
    

if __name__ == "__main__":

    a = App()