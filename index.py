
from NoUpdates import NoUpdates

# from NoUpdates import NoUpdates
from pystray import Icon, MenuItem, Menu
from PIL import Image


def quit_action(icon, item):
    icon.stop()



def main():
    # Create menu for the system tray icon
    menu = Menu(
        MenuItem('Quit', quit_action)
    )

    # Create the icon
    img = Image.open(r'imgs/refresh.png')
    img = img.resize((64, 64)) 

    icon = Icon('test', img, menu=menu)

    # Run the icon
    icon.run()


    tasks_to_end = [
        "updater.exe", "BackgroundDownload.exe"
    ]
    
    nu = NoUpdates(tasks_to_end)

    nu.start()



if __name__ == "__main__":

    main()