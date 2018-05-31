const {app, BrowserWindow, ipcMain} = require('electron')
const spawn = require('child_process').spawn
let win, prc

function createWindow () {
	win = new BrowserWindow({width: 800, height: 600, icon: "logo.png", show: false, frame: false})
	win.loadFile('index.html')

	// Open the DevTools.
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
		prc.kill('SIGHUP')
	}
	if (arg == "init" || arg == "restart") {
		prc = spawn('KatWeb/katweb', ['-root=KatWeb/'])
		prc.stdout.setEncoding('utf8')
		prc.stderr.setEncoding('utf8')
		prc.stdout.on('data', function (data) {
			event.sender.send('asynchronous-message', data.toString())
		});
		prc.stderr.on('data', function (data) {
			event.sender.send('asynchronous-message', '[Error] : ' + data.toString())
		});
		prc.stdin.on('end', function () {
			event.sender.send('asynchronous-message', "[Panel] : KatWeb process has stopped running.\n")
			event.sender.send('asynchronous-reply', "KatWeb is not running.")
		});

		event.sender.send('asynchronous-message', "[Panel] : KatWeb started with pid " + prc.pid + ".\n")
		event.sender.send('asynchronous-reply', "KatWeb PID : " + prc.pid)
	}
})
