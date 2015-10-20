var system = require('system');

url = system.args[1];
filename = system.args[2];
useragent = system.args[3];
timeout = system.args[4];

if (timeout == "") { timeout=1; };   //default is 1 second

function renderPage(url, filename, useragent, timeout) {
	var page = require('webpage').create(), url, filename;
	page.viewportSize = { width: 800, height: 600 };
	page.clipRect = { top: 0, left: 0, width: 800, height: 600 };
	page.settings.userAgent = useragent;
	page.customHeaders = {
		// Nullify Accept-Encoding header to disable compression (https://github.com/ariya/phantomjs/issues/10930)
		'Accept-Encoding': ' ',
	};
	page.onInitialized = function() { page.customHeaders = {}; };

	// Silence confirmation messages and errors
	page.onConfirm = page.onPrompt = page.onError = {};


	var redirectURL = null;
	 
	page.onResourceReceived = function(resource) {
		console.log(resource.url);
		if (url == resource.url && resource.redirectURL) {
			redirectURL = resource.redirectURL;
		}
	};
	 
	page.open(url, function (status) {
		if (redirectURL) {
			console.log('redirected to ' + redirectURL + ' : ' + url);
			renderPage(redirectURL, filename, useragent, timeout);
		} else if (status !== 'success') {
		    //console.log('[Screenshot]  Failed: Unable to load the address.  ' + url);
		    page.close();
		    phantom.exit();
		} else {			
			page.evaluate(function() { document.body.bgColor = 'white'; });
		    window.setTimeout(function () {
		        page.render(filename);
				//console.log('[Screenshot] '+url+' >> ' + filename);
		        page.close();
		        phantom.exit();
		    }, timeout*1000);
		}
	});
}


renderPage(url, filename, useragent, timeout);

