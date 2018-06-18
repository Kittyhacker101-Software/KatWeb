const {app, BrowserWindow, shell, ipcMain, dialog} = require('electron')
const spawn = require('child_process').spawn
const os = require('os')
let win, prc

var path = "KatWeb"

function createWindow() {
	win = new BrowserWindow({width: 450, height: 463, icon: "logo.png", title: "KatWeb Control Panel", show: false, frame: false, resizable: false, webPreferences: {webgl: false, webaudio: false}})
	win.loadFile('index.html')

	//win.webContents.openDevTools()

	win.once('ready-to-show', () => {
		win.show()
	})
	win.on('closed', () => {
		win = null
	})
	win.on('unresponsive', () => {
		win.reload()
	})
	win.webContents.on('crashed', () => {
		win.reload()
	})
}

app.on('ready', createWindow)
app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit()
	}
})
app.on('activate', () => {
	if (win === null) {
		createWindow()
	}
})
app.on('browser-window-created',function(e,window) {
	window.setMenu(null);
});

ipcMain.on('asynchronous-message', (event, arg) => {
	if (arg == "folder") {
		shell.showItemInFolder(path + '/.')
	}
	if (arg == "copy") {
		event.sender.send('asynchronous-message', "[Panel] : Selected text copied to clipboard!\n")
	}
	if (arg == "config") {
		shell.openItem(path + '/conf.json')
	}
	if (arg == "restart") {
		prc.stdout.destroy()
		prc.stderr.destroy()
		prc.stdin.destroy()
		event.sender.send('asynchronous-reply', "clear")
	}
	if (arg == "kill" || arg == "restart") {
		prc.kill('SIGTERM')
	}
	if (arg == "reload") {
		if (os.platform() == "win32") {
			event.sender.send('asynchronous-message', "[Panel] : Reloading configuration is not currently supported on Windows.\n")
			return
		}
		prc.kill('SIGHUP')
	}
	if (arg == "init" || arg == "restart") {
		prc = spawn(path + "/katweb-bin", ['-root=' + path + '/'])
		if (prc.pid == undefined) {
			event.sender.send('asynchronous-message', "[PanelError] : Unable to locate KatWeb.\n")
			event.sender.send('asynchronous-reply', "err")
			return
		}

		prc.stdout.setEncoding('utf8')
		prc.stderr.setEncoding('utf8')
		prc.stdout.on('data', function (data) {
			event.sender.send('asynchronous-message', data.toString())
		});
		prc.stderr.on('data', function (data) {
			event.sender.send('asynchronous-message', data.toString())
		});
		prc.stdin.on('end', function () {
			event.sender.send('asynchronous-message', "[Panel] : KatWeb process has stopped running.\n")
			event.sender.send('asynchronous-reply', "not")
		});

		prc.on('close', function (code) {
			if (code == 1) {
				event.sender.send('asynchronous-reply', "err")
				event.sender.send('asynchronous-message', "[Panel] : KatWeb has crashed!\n");
			}
		});

		event.sender.send('asynchronous-message', "[Panel] : KatWeb started with pid " + prc.pid + ".\n")
		event.sender.send('asynchronous-reply', prc.pid)
	}
})

dialog.showErrorBox = function(title, content) {
	console.error(`${title}\n${content}`);
}
