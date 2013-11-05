var page = require('webpage').create(), url, filename, size;
url = phantom.args[0];
filename = phantom.args[1];
useragent = phantom.args[2];
timeout = phantom.args[3];
if (timeout == "") { timeout=1; };   //default is 1 second
page.viewportSize = { width: 800, height: 600 };
page.clipRect = { top: 0, left: 0, width: 800, height: 600 };
page.settings.userAgent = useragent;
page.open(url, function (status) {
    if (status !== 'success') {
        //console.log('[Screenshot]  Failed: Unable to load the address.  ' + url);
        page.close();
    } else {
		page.evaluate(function() { document.body.bgColor = 'white'; });
        window.setTimeout(function () {
            page.render(filename);
		    //console.log('[Screenshot] '+url+' >> ' + filename);
            page.close();
        }, timeout*1000);
    };
});