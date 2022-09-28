
"use strict";

var id, ini = [];
var reqlisteners = {}, resplisteners = {}, results = {}, legitimatePercents = {}, isPhish = {};
var dnd = false;

function reload(tid) {
	chrome.tabs.reload(tid);
}

function fetchLive(callback) {
  $.getJSON("js/classifier.json", function(data) {
    
      chrome.storage.local.set({cache: data, cacheTime: Date.now()}, function() {
          callback(data);
      });
  });
}

function fetchCLF(callback) {
  chrome.storage.local.get(['cache', 'cacheTime'], function(items) {
      if (items.cache && items.cacheTime) {
          return callback(items.cache);
      }
      fetchLive(callback);
  });
}

function classify(tabId, result) {
  
  var legitimateCount = 0;
  var suspiciousCount = 0;
  var phishingCount = 0;
  for(var key in result) {
    if(result[key] == "1") phishingCount++;
    else if(result[key] == "0") suspiciousCount++;
    else legitimateCount++;
  }
  
  var newEv = legitimateCount / (phishingCount+suspiciousCount+legitimateCount) * 100;

  legitimatePercents[tabId] = newEv;

  if(result.length != 0) {
    var X = [];
    X[0] = [];
    for(var key in result) {
        X[0].push(parseInt(result[key]));
    }

    fetchCLF(function(clf) {
		var rf = random_forest(clf);
		const y = rf.predict(X);
		console.log('Prediction: ' + y[0][0]);
		if(y[0][0] && !getDnD()) {
			isPhish[tabId] = true;
			chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
				if(!isMuted(tabs[0].url)){
					chrome.tabs.sendMessage(tabs[0].id, {action: "alert_user"}, function(response) { });
					console.log('Its not muted')
				}
			});
		} else {
			isPhish[tabId] = false;
		}
    });
  }
}

function inspectPage(id,url) {
	
        if (url == "" || url == undefined || url == "chrome:" || url == "chrome://newtab/" || url == "chrome-extension:" || url == "chrome-plugins:" || url == "chrome-apps:" || url == "chrome-themes:" || url == "chrome-games:" || url == "edge:" || url == "edge://newtab/" || url == "edge://newtab" || url == "edge-extension:" || url == "edge://extensions" || url == "edge-plugins:" || url == "edge-apps:" || url == "edge-themes:" || url == "edge-games:" || url == "about:addons" || url == "about:debugging" || url == "moz-extension:" || url == "about:" || url == "about:newtab") {
			return;
		} else {

				chrome.tabs.create({
					url: "inspect.html?tid=" + id + "&r=context-menu&url=" + url,
					active: true
				}, function() {
					setTimeout(function() {
						reload(id);
					},1000);
				});
				chrome.storage.local.get(null, function(g) {
					if(!g.bl) {
						$.get("js/lib/bl.txt", function(data){
							var bl = data.split('\n');
							g.bl = bl;
							chrome.storage.local.set(g);
						});
					}
				});

				if (reqlisteners[id]) {
					// Callback was previously set. Remove the listeners.
				} else {
					reqlisteners[id] = function(iReq) {
						chrome.runtime.sendMessage({content: iReq, type: "wrq"});
						if (iReq.initiator) {
							ini = iReq.initiator.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
						} else {
							ini = "";
						}
					};
					chrome.webRequest.onSendHeaders.addListener(reqlisteners[id], {
						urls: ["<all_urls>"],
						tabId: id,
					}, ["requestHeaders"]);
					// Show indicator to show that the extension is active
					chrome.browserAction.setBadgeText({
						text: 'ON',
						tabId: id
					});
					chrome.browserAction.setBadgeBackgroundColor({
						color: '#206907',
						tabId: id
					});
				}
				if (resplisteners[id]) {
					// Callback was previously set. Remove the listeners.
				} else {
					resplisteners[id] = function(iResp) {
						chrome.runtime.sendMessage({content: iResp, type: "wrp"});				
					};
					chrome.webRequest.onResponseStarted.addListener(resplisteners[id], {
						urls: ["<all_urls>"],
						tabId: id
					}, ["responseHeaders"]);
					// Show indicator to show that the extension is active.
				}
		}
        
   // });
	// Remove obsolete listener when the tab is closed
	chrome.tabs.onRemoved.addListener(function(id) {
		if (reqlisteners[id]) {
			chrome.webRequest.onBeforeSendHeaders.removeListener(reqlisteners[id]);
			delete reqlisteners[id];
		}
		return true;
	});
}

function openNewTab(url) {
	
	chrome.tabs.create({
		url: url,
		active: true
	}, function(t) {
		console.log(t.id);
		inspectPage(t.id,url);
	});
}

function inspectExisting(){
	chrome.tabs.query({active: true, currentWindow: true}, function (tab) {
		var url = tab[0].url;
		var id = tab[0].id;
		inspectPage(id,url);
	});
}

function openNew(){
    chrome.tabs.create({
		url: "../inspect.html",
		active: true
	})
}

function setDnD(active){
	localStorage.setItem('dnd', active);
	if(active == 'true'){
		dnd = true;
	} else {
		dnd = false;
	}
	
}

function getDnD(){
	var dnd = localStorage.getItem('dnd');
	if(dnd == 'true'){
		dnd = true;
		return true;
	} else {
		localStorage.setItem('dnd', 'false');
		dnd = false;
		return false;
	}
}

function toggleIcon(){
	if(dnd){
		chrome.browserAction.setIcon({path: 'detective-1.png'});
	} else {
		chrome.browserAction.setIcon({path: 'detective.png'});
	}
}

function getIndexesForSite(url){
	var index = localStorage.getItem(urlToHash(url));
	if (index === null) {
		//Entrydoesnexist
		return [];
	} else {
		return index.split(',');
	}
}
// Convert to 32bit integer
function urlToHash(string) {
    var hash = 0;     
    if (string.length == 0) return hash;    
    for (var i = 0; i < string.length; i++) {
        var char = string.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }   
	var hashed = hash.toString();
	if(hashed.includes('-'))
		hashed.replace('-','');

    return hashed;
}

function checkTrackingScore(id,url){
	var hashed = urlToHash(url);
	var index = localStorage.getItem(hashed);
	var legProc = legitimatePercents[id];
	var splitIndex = [];
	if (index === null) {
		//Entry doesnt exist
		var prc = [];
		prc.push(legProc);
		localStorage.setItem(hashed, prc.toString())
	} else {
		splitIndex = index.split(',');
		//it exist so add new if different
		if(splitIndex.length == 0) return;

		if(splitIndex.length == 1){
			if(parseFloat(splitIndex[0]) != legProc){
				splitIndex.push(legProc);
				localStorage.setItem(hashed, splitIndex.toString());
				console.log('Score changed');
			} else {
				console.log('Score not changed');
			}
		} else {
			if(parseFloat(splitIndex[splitIndex.length-2]) != legProc){
				splitIndex.push(legProc);
				localStorage.setItem(hashed, splitIndex.toString());
				console.log('Score changed');
			} else {
				console.log('Score not changed');
			}
		}
	}
}

function removeFromMuted(url){
	var hh = urlToHash(url);
	var muted = localStorage.getItem('muted');
	
	if(muted === null) return; //default
	var splMuted = muted.split(',');
	if(splMuted.length == 0) {
		return;
	} else if (splMuted.length == 1){
		if(splMuted[0] == hh){
			localStorage.removeItem('muted');
		}
	} else {	
		for(var i = 0; i < splMuted.length; i++){ 
			if (splMuted[i] === hh) { 
				splMuted.splice(i, 1); 
				localStorage.setItem('muted', splMuted.toString());
			}
		}
	}
}

function addToMuted(url){
	var hh = urlToHash(url);
	var muted = localStorage.getItem('muted');
	
	if(muted === null){
		var arr = [];
		arr.push(hh);
		localStorage.setItem('muted', arr.toString());
		console.log(arr)
		return;
	}
	var splMuted = muted.split(',');
	if(splMuted.length == 0) {
		var arr = [];
		arr.push(hh);
		localStorage.setItem('muted', arr.toString());
		console.log(arr)
	} else if (splMuted.length == 1){
		if(splMuted[0] != hh ){
			splMuted.push(hh);
			localStorage.setItem('muted', splMuted.toString());
			console.log(splMuted)
		}
	} else {
		if(!splMuted.includes(hh)){
			splMuted.push(hh);
			localStorage.setItem('muted', splMuted.toString());
			console.log(splMuted)
		}
	}
}

function isMuted(url){
	var hh = urlToHash(url);
	var muted = localStorage.getItem('muted');
	if(muted === null) return false; //default
	var splMuted = muted.split(',');
	console.log(splMuted + url)
	if(splMuted.length == 0) {
		return false;
	} else if(splMuted.length == 1){
			if(splMuted[0] == hh){
				console.log('shoud be muted')
				return true;
			} else {
				console.log('shoudnt be muted')
				return false;
			}
	} else {
		if(splMuted.includes(hh)){
			console.log('shoud be muted')
			return true;
		} else {
			console.log('shoudnt be muted')
			return false;
		}
	}

}

chrome.contextMenus.removeAll(function() {
	var cm1 = chrome.contextMenus.create({
		contexts:  ['link'],
		title : 'Inspect link with DeepPhish',
		onclick: function(link){openNewTab(link.linkUrl)}
	});
	var cm2 = chrome.contextMenus.create({
		contexts:  ['page'],
		title : 'Inspect page with DeepPhish',
		onclick: inspectExisting
	});
});

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
	results[sender.tab.id]=request;
	classify(sender.tab.id, request);
	sendResponse({received: "result"});
	checkTrackingScore(sender.tab.id,sender.tab.url);
	return true;
});
  
chrome.runtime.onMessage.addListener(function(get) {
	if(get.type == "openerTabId") {
		console.log("openerTabId: ", get.content);
		inspectPage(get.content[0],get.content[1]);
	}
	return true;
});