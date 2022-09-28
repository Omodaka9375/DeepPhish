var d, url,protocol, status, cType, cLen, gmapskey, domainRep, phishTank, safeBrowse, hackerTarget;
var urlToCheck = [], domainToCheck = [], domainslist = [];
var refusedToLoadOnFrame = "DENY";
var AS = "/ads.txt";
var flagMalware, flagPhish, flagNonSSL, flagRedirect, flagFlash, flagVideo, flagAudio, flagNotFound, flagBadRequest, flagXhr, flagFrame, flagScript, flagImage, flagStylesheet, flagFont, flagMedia, flagAds, flagCsp, flagObject, flagPing, flagWebsocket, flagAnaly, flagDns, flagOthers, flagNewDomain, flagReputation, toastMalware, toastPhish, toastNewDomain;
flagMalware = id = ir = flagPhish = flagNonSSL = flagRedirect = flagFlash = flagVideo = flagAudio = flagNotFound = flagBadRequest = flagXhr = flagFrame = flagScript = flagImage = flagStylesheet = flagFont = flagMedia = flagAds = flagCsp = flagObject = flagPing = flagWebsocket = flagAnaly = flagDns = flagOthers = flagNewDomain = flagReputation = toastMalware = toastPhish = toastNewDomain = 0;

function setTooltip(e) {
	$(e).tooltip('hide')
		.attr('title', 'Copied!')
		.attr('data-toggle','tooltip')
		.attr('data-placement','bottom')
		.tooltip('show');
}

function hideTooltip(e) {
  setTimeout(function() {
    $(e).tooltip('hide');
  }, 1000);
}

function dt() {
	var cDate = new Date(); 
    var dt = cDate.getFullYear() + "-" + (cDate.getMonth()+1)  + "-" +  cDate.getDate();
	return dt;
}

function copyToClipboard(element) {
	var tempElem = $("<textarea>");
	$("body").append(tempElem);
	switch(element) {
		case '#whois pre':
			var html = $(element).text();
			break;
		case '#srcCodePre':
			var html = $(element).text();
			break;
		case '#fdns pre':
			var html = $(element).html();
			html = html.replace(/<br>/g, "\n"); // or \r\n
			html = html.replace(/ /g, "\n");
			break;
		case '#dList':
			var html = $(element).html();
			html = html.replace(/<br>/g, "\n"); // or \r\n
			html = html.replace(/ /g, "\n");
			break;
		case '#ads .card-text':
			var html = $(element).text() + "\n\n" + $("#app-ads .card-text").text();
			break;
		case '#https-links':
			var html = "Internal-links:\n\n" + $(element).text() + $("#http-links").text() + "\n\nExternal-links:\n" + $("#external-links").text();
			html = html.replace(/ /g, "\n");
			break;
		default:
			var html = $(element).text();
			html = html.replace(/<br>/g, "\n"); // or \r\n
			html = html.replace(/ /g, "\n");
			break;
	}
  	tempElem.val(html).select();
  	document.execCommand("copy");
  	tempElem.remove();
}

function dwld(item,itemToSave) {
	var hiddenElem = document.createElement('a');
    hiddenElem.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(itemToSave);
//    hiddenElem.target = '_blank';
    hiddenElem.download = d + " - " + item + " - " + dt() + ".txt";
    hiddenElem.click();
	hiddenElem.remove();
}

function saveAsTxt(item) {
	switch(item) {
		case 'Page Source':
			var itemToSave = $("#srcCodePre")[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'Page Source']);
			break;
		case 'Whois Lookup':
			var itemToSave = $("#whois pre")[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'Whois']);
			break;
		case 'Extracted domain list':
			var itemToSave = $("#dList")[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'Domain List']);
			break;
		case 'Page Links':
			var itemToSave = $('#https-links')[0].innerText + $('#http-links')[0].innerText + $('#external-links')[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'Page Links']);
			break;
		case 'DNS Lookup':
			try {
				var itemToSave = $("#fdns pre")[0].innerText + $("#rdns p")[0].innerText;
			}
			catch {
				var itemToSave = $("#fdns pre")[0].innerText;
			}
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'DNS']);
			break;
		case 'Subdomain':
			var itemToSave = $("#subDomainResults")[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'Subdomain']);
			break;
		case 'Authorized Digital Sellers':
			var itemToSave = $("#ads .card-text")[0].innerText + $("#app-ads .card-text")[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'ads.txt']);
			break;
		case 'Domain Reputation':
			var itemToSave = $("#urlReputation")[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'Reputation']);
			break;
		case 'Crawlers':
			var itemToSave = $("#webCrawlers .card-text")[0].innerText;
			dwld(item,itemToSave);
			//_gaq.push(['_trackEvent', 'Download', 'success', 'robots.txt']);
			break;
		default:
			break;
	}
}

function dListGraph() {
	var dListGraphData = [];
	//console.log("dList: ", domainslist);
	
	for (i=1;i<domainslist.length;i++){
		dListGraphData.push([d,domainslist[i]]);
	}
	var l0Color = "#2AA775",
		l1Color = "#FFD265";
	
	Highcharts.chart('dListGraph', {
		chart: {
			type: 'networkgraph'
		},
        credits: {
            enabled: false
        },
		title: {
			text: ''
		},
		subtitle: {
			text: ''
		},
		tooltip:{
			formatter:function(){
				var info="";
				switch(this.color){
					case l0Color: 
						info = url+"<br>"
						break;
				}
				return "<b>"+this.key + "</b>: "+info;
			}
		},
		plotOptions: {
			networkgraph: {
		  keys: ['from', 'to'],
		  layoutAlgorithm: {
			  enableSimulation: true,
			  friction: -0.9,
			  integration: 'verlet',
			  linkLength: 140
		  }
		}
	  },
	  series: [{
		  marker: {
			  radius: 6,
		  },
		  allowOverlap: false,
		  color: l1Color,
		  dataLabels: {
			  enabled: true,
			  linkFormat: '',
			  allowOverlap: true,
			  style: {
				  textOutline: false
			  }
		  },
		  id: 'dListGraphData',
		  data: dListGraphData,
		  nodes: [{
			  id: d,
			  marker: {
				  radius: 9,
			  },
			  color: l0Color,
			  dataLabels: {
				  enabled: true,
				  style: {
					  fontFamily: 'sans-serif',
					  fontSize: '16px'
				  }
			  }
		  },]
	  }],
		exporting: {
			onoffline: true,
			filename: d + " - " + dt(),
			sourceWidth: 1200,
			sourceHeight: 800,
//			scale: 2,
			buttons: {
				contextButton: {
					menuItems: ['viewFullscreen', 'printChart', 'downloadPNG', 'downloadJPEG', 'downloadSVG']
				}
			}
		}
	});
}

function geoIP(d) {
	try {
        $.ajax({
            type: "GET",
            url: "http://ip-api.com/json/"+d+"?fields=30146559",
			dataType: "json",
			async: true,
            success: function(o){
				if (o.status == "success") {
					$("#geo-ip-location .card-title")[0].innerText = "Domain: " + d;
					$("#geo-ip-location .card-title")[1].innerText = "IP Address: " + o.query;
					var tr = $("#geo-ip-location table tbody");
					var lat, lot;
					$.each(o, function(k, v){
						if (v === "" || v === null){
							delete o[k];
						} else {
							switch (k) {
								case "country":
									tr.append("<tr><th scope='row'>Country</th><td>"+v+"</td></tr>");
									break;
								case "countryCode":
									tr.append("<tr><th scope='row'>Country code</th><td>"+v+"</td></tr>");
									break;
								case "region":
									tr.append("<tr><th scope='row'>Region/state short code</th><td>"+v+"</td></tr>");
									break;
								case "regionName":
									tr.append("<tr><th scope='row'>Region/state</th><td>"+v+"</td></tr>");
									break;
								case "city":
									tr.append("<tr><th scope='row'>City</th><td>"+v+"</td></tr>");
									break;
								case "district":
									tr.append("<tr><th scope='row'>District</th><td>"+v+"</td></tr>");
									break;
								case "zip":
									tr.append("<tr><th scope='row'>Zip code</th><td>"+v+"</td></tr>");
									break;
								case "lat":
									lat = v;
									tr.append("<tr><th scope='row'>Latitude</th><td>"+v+"</td></tr>");
									break;
								case "lon":
									lot = v;
									tr.append("<tr><th scope='row'>Longitude</th><td>"+v+"</td></tr>");
									break;
								case "timezone":
									tr.append("<tr><th scope='row'>Timezone</th><td>"+v+"</td></tr>");
									break;
								case "currency":
									tr.append("<tr><th scope='row'>Currency</th><td>"+v+"</td></tr>");
									break;
								case "isp":
									tr.append("<tr><th scope='row'>ISP</th><td>"+v+"</td></tr>");
									break;
								case "org":
									tr.append("<tr><th scope='row'>Organization</th><td>"+v+"</td></tr>");
									break;
								case "isp":
									tr.append("<tr><th scope='row'>ISP</th><td>"+v+"</td></tr>");
									break;
								case "as":
									tr.append("<tr><th scope='row'>AS Number and Organization</th><td>"+v+"</td></tr>");
									break;
								case "asname":
									tr.append("<tr><th scope='row'>AS Name</th><td>"+v+"</td></tr>");
									break;
								case "reverse":
									tr.append("<tr><th scope='row'>Reverse DNS of the IP</th><td>"+v+"</td></tr>");
									break;
								case "mobile":
									tr.append("<tr><th scope='row'>Mobile (cellular) connection</th><td>"+v+"</td></tr>");
									break;
								case "proxy":
									tr.append("<tr><th scope='row'>Proxy, VPN or Tor exit address</th><td>"+v+"</td></tr>");
									break;
								case "hosting":
									tr.append("<tr><th scope='row'>Reverse DNS of the IP</th><td>"+v+"</td></tr>");
									break;
								default:
									break;
							}
						}
					}); //KEY
					$("#geo-ip-location iframe").attr("src","https://www.google.com/maps/embed/v1/view?key=" + gmapskey + "&center="+lat+","+lot+"&zoom=12");
				
				} else {
					$("#geoIP").hide();
				}
			},
			error: function(err) {
                console.log("Whois Lookup: ", err);
				$("#geoIP").hide();
				//_gaq.push(['_trackEvent', 'GeoIP', 'fail', 'URL Inspect']);
            }
        });
	}
	
	catch(err) {
        console.log("GeoIP Lookup: ", err);
		$("#geoIP").hide();
		//_gaq.push(['_trackEvent', 'GeoIP', 'fail', 'URL Inspect']);
    }
}

function whois(d) {
	var dd = d.split(".").reverse();
	//console.log(dd);
    try {
        $.ajax({
            type: "GET",
            url: "https://api.hackertarget.com/whois/?q=" + dd[1]+"."+dd[0]+"&apikey="+ hackerTarget,
			dataType: "text",
			async: true,
            success: function(data){
				//console.log("Whois call success: " + data);
				switch (data) {
					case "error input invalid - enter IP or Hostname":
						$("#whois pre").append("Failed to perform Whois lookup, please try <a href='https://lookup.icann.org/lookup' target='_blank' >ICANN's Whois Lookup</a>");
						break;
					case "API count exceeded - Increase Quota with Membership":
						$("#whois pre").append("Failed to perform Whois lookup, please try <a href='https://lookup.icann.org/lookup' target='_blank' >ICANN's Whois Lookup</a>");
						break;
					case "error check your api query":
						$("#whois pre").append("Failed to perform Whois lookup, please try <a href='https://lookup.icann.org/lookup' target='_blank' >ICANN's Whois Lookup</a>");
						break;
					case "API":
						$("#whoisLookup").hide();
						break;
					default:
						$("#whois pre").text(data);
						var arrWhois = data.split(" ");
						//console.log(arrWhois);
						for (var i=0;i<=arrWhois.length;i++) {
							if (arrWhois[i] == "Expiry") {
								var expiryDt = arrWhois[i+2];
							}
							if (arrWhois[i] == "Updated") {
								var updatedDt = arrWhois[i+2];
							}
							if (arrWhois[i] == "Creation") {
								var creationDt = arrWhois[i+2];
							}
						}
						if (creationDt) {
							//console.log(arrWhois[i+2]);
							var creationYr = creationDt.split('T')[0].split('-')[0];
							//console.log("creationYr: ", creationYr);
							var todayDt = new Date();
							var flagCaution = todayDt.getFullYear() - creationYr;
							if (flagCaution == 1 || flagCaution == 0) {
								if (flagNewDomain == 0) {
									newDomainTag = "<span class='badge badge-warning'>" + 'New domain' + "</span>";
									$('#tagsDetected').append(newDomainTag);
									$('#tagsDetected').show();
									flagNewDomain = 1;
								}
								//toastNewDomain
								if (toastNewDomain == 0) {
									$("#toastNewDomain").append("<div class='toast-header'><img src='../img/warning.png' class='rounded mr-2' alt=''><strong class='mr-auto'>Caution</strong><small class='text-muted'></small><button type='button' class='ml-2 mb-1 close' data-dismiss='toast' aria-label='Close'><span aria-hidden='true'>&times;</span></button></div></div>");
									$("#toastNewDomain").append("<div class='toast-body'><div class='row' style='margin:1px'><span>Creation date: "+creationDt+"</span><span>Updated date: "+updatedDt+"</span><span>Expiry date: "+expiryDt+"</span></div><div class='myRow'><ul><li>The creation of this domain name is rather recent</li><li>Short life expectancy domain</li><li>This domain name is linked to one or more regions known for being used by fraudulent websites</li></ul></div></div>");
									toastNewDomain = 1;
								}
								$('#toastNewDomain').toast('show');
							}
						}
						break;
				}
            },
            error: function(err) {
                //console.log("Whois Lookup: ", err);
				$("#whois pre").append("Failed to perform Whois lookup, please try <a href='https://lookup.icann.org/lookup' target='_blank' >ICANN's Whois Lookup</a>");
            }
        });
    } catch(err) {
        //console.log("Whois Lookup: ", err);
		$("#whois pre").append("Failed to perform Whois lookup, please try <a href='https://lookup.icann.org/lookup' target='_blank' >ICANN's Whois Lookup</a>");
    }
}

function subdomain(d) {
	//console.log("called subdomain: ", d);
	try {
        $.ajax({
            type: "GET",
            url: "https://api.hackertarget.com/hostsearch/?q=" + d +"&apikey="+ hackerTarget,
			dataType: "text",
			async: true,
            success: function(data){
				switch (data) {
					case "error input invalid - enter IP or Hostname":
						$("#subDomain").hide();
						break;
					case "API count exceeded - Increase Quota with Membership":
						$("#subDomain").hide();
						break;
					case "API":
						$("#subDomain").hide();
						break;
					default:
						$("#subDomainResults").text(data);
						break;
				}
				//_gaq.push(['_trackEvent', 'Subdomain', 'success', 'URL Inspect']);
            },
            error: function(err) {
                //console.log("Subdomain Lookup: ", err);
				$("#subDomain").hide();
				//_gaq.push(['_trackEvent', 'Subdomain', 'fail', 'URL Inspect']);
            }
        });
    }
    
    catch(err) {
        //console.log("Whois Lookup: ", err);
		$("#subDomain").hide();
		//_gaq.push(['_trackEvent', 'Subdomain', 'fail', 'URL Inspect']);
    }
}

function dns(url) {
	try {
        $.ajax({
            method: "GET",
            url: "https://api.hackertarget.com/dnslookup/?q=" + url, //+ "&apikey="+ hackerTarget,
			async: true,
            success: function(data){
				$("#dns_data").append(data);
            },
            error: function(err) {
                 console.log("DNS Lookup: ", err);
				$("#dns_data").hide();
            }
        });
    }
    
    catch(err) {
        console.log("DNS Lookup: ", err);
		$("#dns_data").hide();
    }
}

function removeDuplicateItems(id) {
    var ul = $('#' + id);
    $('li', ul).each(function() {
        if($('li:contains("' + $(this).text() + '")', ul).length > 1)
            $(this).remove();
    });
}

var getUrlParameter = function getUrlParameter(sParam) {
    var sPageURL = decodeURIComponent(window.location.search.substring(1)),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : sParameterName[1];
        }
    }
};

function pageSource(resp) {
	$('#srcCodePre').text(resp);
	$('pre#srcCodePre').litelighter({
		style: 'light',
		language: 'html'
	});
	$('#srcCodePre').css('min-height','600px');
	$('#srcCodePre').css('word-break','break-all');
	$('#srcCodePre').css('word-wrap','break-word');
	$('#srcCodePre').css('white-space','pre');
	$('#srcCodePre').css('white-space','-moz-pre-wrap');
	$('#srcCodePre').css('white-space','pre-wrap');
	$('#srcCodePre').css('white-space','pre\9');
}

function extractLinks(url) {
	$.ajax({
		type: "GET",
		url: url,
		cache: false,
		async: true,
		dataType: "html",
		success: function(resp) {
			pageSource(resp);
			var parsedResponse = $.parseHTML(resp);
        	var res = $(parsedResponse).find("a");
			for (var i=0;i<res.length;i++) {
				if (res[i].href.indexOf(d) > -1) {
					$('#intDiv').show();
					if ((res[i].href.startsWith("https://") == true) && (/\/inspect.html/i.test(res[i].href) == false)) {
						$('#intDiv p:first').show();
						$('#https-links').append("<li><a href='"+ res[i].href +"' target='_blank'> "+ res[i].href +" </a></li>");
					} else if ((res[i].href.startsWith("http://") == true) && (/\/inspect.html/i.test(res[i].href) == false)) {
						$('#intDiv p:last').show();
						$('#http-links').append("<li><a href='"+ res[i].href +"' target='_blank'> "+ res[i].href +" </a></li>");
						if (flagNonSSL == 0) {
							$('#tagsDetected').css('display','block');
							nonsslTag = "<span class='badge badge-danger'>Non-secure</span>";
							$("#tagsDetected").append(nonsslTag);
							flagNonSSL = 1;
						}
					}
				} else if (res[i].href.startsWith("https://") == false && res[i].href.startsWith("http://") == false) {
					$('#https-links').append("<li><a href='https://"+ d + res[i].pathname +"' target='_blank'>https://"+ d + res[i].pathname +" </a></li>"); 
				} else {
					$('#extDiv').show();
					$('#external-links').append("<li><a href='"+ res[i].href +"' target='_blank'> "+ res[i].href +" </a></li>");
				}
			}
        },
		error: function(xhr, ajaxOptions, thrownError) {
			if(xhr.status == 404) {
				//console.log("Error fn extractLinks: ", xhr.status, thrownError);
			}
		}
	});
	$(document).ajaxComplete(function() {
	  	removeDuplicateItems("https-links");
		removeDuplicateItems("http-links");
		removeDuplicateItems("external-links");
	});
}

function ads(d) {
	try {
		$.ajax({
			type: "GET",
			url: "https://" + d + AS,
			cache: false,
			async: true,
			dataType: "text",
			success: function(resp) {
				$("#ads .card-text").text(resp);
				$("#ads").show();
				if (flagAds == 0) {
					adsTag = "<span class='badge badge-primary'>" + 'Ads' + "</span>";
					$('#tagsDetected').append(adsTag);
					$('#tagsDetected').show();
					flagAds = 1;
				}
			},
			error: function(xhr, ajaxOptions, thrownError) {
				if(xhr.status !== 200) {
					$("#inspectAds").hide();
				}
			}
		});
	}
	catch(err) {
		$("#inspectAds").hide();
    }
}

function appAds(d) {
	try {
		$.ajax({
			type: "GET",
			url: "https://" + d + "/app-" + AS.split('/')[1],
			cache: false,
			async: true,
			dataType: "text",
			success: function(resp) {
				$("#app-ads .card-text").text(resp);
				$("#app-ads").show();
				if (flagAds == 0) {
					adsTag = "<span class='badge badge-primary'>" + 'Ads' + "</span>";
					$('#tagsDetected').append(adsTag);
					$('#tagsDetected').show();
					flagAds = 1;
				}
				//_gaq.push(['_trackEvent', 'app-ads.txt', 'success', 'URL Inspect']);
			},
			error: function(xhr, ajaxOptions, thrownError) {
				if(xhr.status !== 200) {
					//_gaq.push(['_trackEvent', 'app-ads.txt', 'fail', 'URL Inspect']);
					$("#app-ads").hide();
	//				//console.log("Error fn appAds: ", xhr.status, thrownError);
	//				$("#adSlot div").text("No Authorized Digital Sellers for Apps found");
				}
			}
		});
	}
	
	catch(err) {
		$("#app-ads").hide();
		//console.log('no ads found' + err)
		//_gaq.push(['_trackEvent', 'app-ads.txt', 'fail', 'URL Inspect']);
    }
}

function pgArchive(d) {
	try {
		$.ajax({
			type: "GET",
			url: "http://archive.org/wayback/available?url=" + d,
			cache: false,
			async: true,
			dataType: "json",
			success: function(r) {
				if(JSON.stringify(r.archived_snapshots) === '{}'){
					$('#wayback_text').hide();
					$("#pageArchive").hide();
				} else if (r.archived_snapshots.closest.available) {
					$('#wayback_text').wrap('<a href="'+ r.archived_snapshots.closest.url +'" target="_blank"/>');
				} else {
					console.log('Archive not available');
					$('#wayback_text').hide();
					$("#pageArchive").hide();
				}
			},
			error: function(xhr, ajaxOptions, thrownError) {
				if(xhr.status !== 200) {
					console.log("Error fn pgArchive: ", xhr.status, thrownError);
					$('#wayback_text').hide();
					$("#pageArchive").hide();
				}
			}
		});
	}
	
	catch(err) {
		console.log('Archive not available - Error')
		$("#pageArchive").hide();
    }
}

function domainReputation(d) {
	//console.log("domainReputation: ", d);
	try {
		$.ajax({
			type: "GET",
			url: "https://domain-reputation.whoisxmlapi.com/api/v1?apiKey=" + domainRep + "&domainName=" + d,
			async: true,
			success: function(r) {
				//console.log(r);
				if (r.reputationScore > 80) {
					if (flagReputation == 0) {
						reputationTag = "<span class=\"badge badge-success\">Reputation Score <span class=\"badge badge-success\" style=\"margin:0;padding:1.9px\">" + r.reputationScore + "</span></span>";
						$('#tagsDetected').append(reputationTag);
						$('#tagsDetected').show();
						flagReputation = 1;
					}
					$("#dRepScore").text(r.reputationScore);
				} else if (r.reputationScore > 30 && r.reputationScore <= 80) {
					if (flagReputation == 0) {
						reputationTag = "<span class=\"badge badge-warning\">Reputation Score <span class=\"badge badge-warning\" style=\"margin:0;padding:1.9px\">" + r.reputationScore + "</span></span>";
						$('#tagsDetected').append(reputationTag);
						$('#tagsDetected').show();
						flagReputation = 1;
					}
					$("#dRepScore").css("class","badge badge-warning");
					$("#dRepScore").text(r.reputationScore);
				} else {
					if (flagReputation == 0) {
						reputationTag = "<span class=\"badge badge-danger\">Reputation Score <span class=\"badge badge-danger\" style=\"margin:0;padding:1.9px\">" + r.reputationScore + "</span></span>";
						$('#tagsDetected').append(reputationTag);
						$('#tagsDetected').show();
						flagReputation = 1;
					}
					$("#dRepScore").css("class","badge badge-danger");
					$("#dRepScore").text(r.reputationScore);
				}
				if (r.testResults) {
					for (var i=0;i<r.testResults.length;i++) {
						if (r.testResults[i].test == "SSL vulnerabilities") {
							$("#urlReputation").append("<h5 class=\"card-title\">"+r.testResults[i].test+"</h5><p class=\"card-text\"></p>");
							for (j=0;j<r.testResults[i].warnings.length;j++) {
								$("#urlReputation").append("<li>"+r.testResults[i].warnings[j]+"</li>");
							}
						} else {
							$("#urlReputation").append("<h5 class=\"card-title\">"+r.testResults[i].test+"</h5><p class=\"card-text\"><li>"+r.testResults[i].warnings+"</li></p>");
						}
					}
				}
			},
			error: function(xhr, ajaxOptions, thrownError) {
				//console.log("domainReputation: failed");
				if(xhr.status !== 200) {
					$("#domain-reputation").hide();
				}
			}
		});
	}
	
	catch(err) {
		$("#domainReputation").hide();
		//_gaq.push(['_trackEvent', 'Reputation', 'fail', 'URL Inspect']);
    }
}

function robots(d) {
	try {
		$.ajax({
			type: "GET",
			url: "https://" + d + "/robots.txt",
			cache: false,
			async: true,
			dataType: "text",
			success: function(resp) {
				$("#webCrawlers .card-text").text(resp);
			},
			error: function(xhr, ajaxOptions, thrownError) {
				if(xhr.status !== 200) {
					$("#crawlers").hide();
				}
			}
		});
	}
	
	catch(err) {
		$("#crawlers").hide();
    }
}

async function cookies(d) {
	try {
		chrome.cookies.getAll({}, function (cookie) {
			if(cookie){
				for (var i=0;i<=cookie.length-1;i++) {
					if (cookie[i].domain.includes(d)) {
						const cc = cookie[i];
						for (var i in cc) {
							$("#cookies-results").append("<b>"+i+"</b>" + ": " + cc[i]+ " <br><br>");
						}
					}
				}
			} else {
				console.log('Cookie fetch error')
				$("#url-cookies").hide();
			}
		});
	} catch (e) {
		console.log('Cookie fetch error: ' + e);
		$("#url-cookies").hide();
	}
}

function notification() {
	chrome.storage.sync.get(null, function(g) {
		if (g.installedNotification) {
			if (g.installedNotification == true) {
				$("#installedModal").modal("show");
				chrome.storage.sync.set({['installedNotification']: false});
			}
		}
		if (g.updatedNotification) {
			if (g.updatedNotification == true) {
				$("#updatedModal").modal("show");
				chrome.storage.sync.set({['updatedNotification']: false});
			}
		}
	});
	
	$("#home").css("display","none");
	$("#scanResults").css("display","block");
	$("#ctPageBgIcon").css("display","block");
	$("#loadingModal").modal("show");
	var etd = 16;
	var loadingTimer = setInterval(function(){
	  if(etd <= 0){
		clearInterval(loadingTimer);
		$("#etd").text("Error occured!");
		  $("#loadingModal .modal-body span").first().append("<br><br><div class='alert alert-warning' role='alert'>Taking longer than expected, please try again or <a href='https://chrome.google.com/webstore/detail/ibbejlanbkoaepocgcebajilofpnappm/support' target='_blank'>report</a> it</div>");
	  } else {
		$("#etd").text(etd + "s");
	  }
	  etd -= 1;
	}, 1000);
}

function pp() {
	chrome.storage.sync.get("privacyPolicy", function(g) {
		if(!g.privacyPolicy) {
			$("#acceptedPP").css("display","block");
			$("#ppModal").modal("show");
			$("#acceptedPP").on('click', function() {
				$("#ppModal").modal("hide");
				chrome.storage.sync.set({['privacyPolicy']: true}, function() {//console.log("pp accepted!");});
			});
				
			});
		}

		})
}

function phishtank(url) {
	//console.log(url);
	$.ajax({
		type: "POST",
		url: "https://checkurl.phishtank.com/checkurl/index.php?url=",
		contentType: "application/x-www-form-urlencoded",
		dataType: "json",
		async: true,
		data: "url=" + encodeURIComponent(unescape(url)) + "&format=" + encodeURIComponent(unescape("json")) + "&app_key=" + encodeURIComponent(unescape(phishTank)),
		success: function(r){
			//console.log(r);
			if (r.meta.status == "success" && r.results.in_database == true) 
			{
				if (r.results.valid == true) {
					if (flagPhish == 0) {
						phishTag = "<span class='badge badge-danger'>" + 'Phishing' + "</span>";
						$('#tagsDetected').append(phishTag);
						$('#tagsDetected').show();
						flagPhish = 1;
					}
					//toast phish flag
					var pthd = document.createElement('div');
					var pthi = document.createElement('img');
					var pthst = document.createElement('strong');
					var pthsm = document.createElement('small');
					var pthbtn = document.createElement('button');
					var pthspn = document.createElement('button');
					pthd.setAttribute('class','toast-header');
					pthi.setAttribute('src','../img/malware.png');
					pthi.setAttribute('class','rounded mr-2');
					pthst.setAttribute('class','mr-auto');
					pthst.innerText = "Phishing";
					pthsm.setAttribute('class','text-muted');
					pthbtn.setAttribute('type','button');
					pthbtn.setAttribute('class','ml-2 mb-1 close');
					pthbtn.setAttribute('data-dismiss','toast');
					pthbtn.setAttribute('aria-label','Close');
					pthspn.setAttribute('aria-hidden','true');
					pthspn.innerHTML = "&times;";
					pthd.appendChild(pthi);
					pthd.appendChild(pthst);
					pthd.appendChild(pthsm);
					pthbtn.appendChild(pthspn);
					pthd.appendChild(pthbtn);
					
					var ptbd = document.createElement('div');
					var ptbul = document.createElement('ul');
					var ptbli1 = document.createElement('li');
					var ptbli2 = document.createElement('li');
					var ptbli3 = document.createElement('li');
					var br = document.createElement('br');
					ptbd.setAttribute('class','toast-body');
					ptbul.setAttribute('style','list-style-type:none;margin-left:-30px;word-break: break-all;');
					ptbli1.innerText = r.results.url;
					ptbli2.innerText = "phish_id: " + r.results.phish_id;
					ptbli3.innerText = "verified_at: " + r.results.verified_at;
					
					ptbul.appendChild(ptbli1);
					ptbul.appendChild(br);
					ptbul.appendChild(ptbli2);
					ptbul.appendChild(ptbli3);
					ptbd.appendChild(ptbul);
					
					$("#toastPhish").append(pthd);
					$("#toastPhish").append(ptbd);
					
					toastPhish = 1;
					$('#toastPhish').toast('show');
				} 				
			}
		},
		error: function(e) {
			console.log("Error PhishTank: ", e);
		}
	});
}

function gsb(urlToCheck) {
	var z, y, x, w;
	console.log("urlToCheck: ", urlToCheck);
	const pkg = JSON.parse(JSON.stringify(urlToCheck));
	for (w in pkg) {
		if (pkg[w].url.startsWith("wss://") == false) {
			delete pkg[w].id;
		} else {
			delete pkg[w];
		}
	}
	console.log("pkg: ", pkg);
    try {
        var reqGSB = {
            "client": {
              "clientId": "mz",
              "clientVersion": "0.0.1"
            },
            "threatInfo": {
              "threatTypes": ["MALWARE", "UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
              "platformTypes": ["ANY_PLATFORM", "PLATFORM_TYPE_UNSPECIFIED"],
              "threatEntryTypes": ["URL", "EXECUTABLE", "THREAT_ENTRY_TYPE_UNSPECIFIED"],
              "threatEntries": pkg
            }
        };
        console.log("reqGSB: ", reqGSB);
        $.ajax({
            type: "POST",
            url: "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + safeBrowse,
			contentType: 'application/json',
			dataType: 'json',
			async: true,
            data: JSON.stringify(reqGSB),
            success: function(r){
				if ($.isEmptyObject(r)) {

				} else {
					if (flagMalware == 0) {
						malwareTag = "<span class='badge badge-danger'>" + 'Malicious' + "</span>";
						$('#tagsDetected').append(malwareTag);
						$('#tagsDetected').show();
						flagMalware = 1;
					}
					for (x in r.matches) {
						for (y in urlToCheck) {
							if (urlToCheck[y].url == r.matches[x].threat.url) {
								if (toastMalware == 0) {
									//toast malware flag
									$("#toastMalware").append("<div class='toast-header'><img src='../img/malware.png' class='rounded mr-2' alt=''><strong class='mr-auto'>Malicious</strong><small class='text-muted'></small><button type='button' class='ml-2 mb-1 close' data-dismiss='toast' aria-label='Close'><span aria-hidden='true'>&times;</span></button></div></div>");
									$("#toastMalware").append("<div class='toast-body'><ul style='list-style-type:none;margin-left:-30px;word-break: break-all;'><li>"+r.matches[x].threat.url+"</li><br><li>Threat Entry Type: "+r.matches[x].threatEntryType+"</li><li>Threat Type: "+r.matches[x].threatType+"</li><li>Platform Type: "+r.matches[x].platformType+"</li></ul></div>");
									toastMalware = 1;
								}
								//flag on table
								var ltTable = $("#liveNetworkTraffic tbody tr").length;
								for (z=0;z<ltTable;z++) {
									var row = $("#liveNetworkTraffic tbody tr")[z].id;
									if (row == urlToCheck[y].id) {
										//console.log("row: ", row);
										$("#" +row).children('td').eq(4).append("<span class='malware'>malicious</span>");
									}
								}
							}
						}
					}
					$('#toastMalware').toast('show');
				}
            },
            error: function(e) {
                console.log("Error GSB: ", e);
            }
        });
    }
    
    catch(e) {
        console.log("Error GSB: ", e);
		//_gaq.push(['_trackEvent', 'GSB', 'fail', 'URL Inspect']);
    }
}
/**
* Check the Chrome browser is in Incognito mode or not
*
*/
function chkIncognitoMode() {
    var fs = window.RequestFileSystem || window.webkitRequestFileSystem;
    if (!fs) {
//        infoIncognito.textContent = "check failed?";
//        return;
    }
    fs(window.TEMPORARY, 100, function(fs) {

        infoIncognito.textContent = "Recommend to use DeepPhish on Chrome Incognito mode.";
        $('#infoIncognito').show(1000);
        setTimeout(function(){ $('#infoIncognito').hide(1000);}, 6000);
    }, function(err) {
        $('#infoIncognito').css('display','none');
//        result.textContent = "it seems like you are in incognito mode";
    });
}

function callExport () {
    $('#exportIcon').click(function() {
       liveTableFn();
        $('#exportWrap').css('display','none');
    });
}

function callChaintree () {
    var tree = document.getElementById("tree");
    var lists = [ tree ];
     
      for (var i = 0; i < tree.getElementsByTagName("ul").length; i++)
        lists[lists.length] = tree.getElementsByTagName("ul")[i];

      for (var i = 0; i < lists.length; i++) {
        var item = lists[i].lastChild;
     	 
        while (!item.tagName || item.tagName.toLowerCase() != "li")
     	  item = item.previousSibling;

        item.className += " last";
      }
}

function liveTableFn() {
	var currentDT = new Date();
    $("#liveNetworkTraffic").tableExport({
        headings: true,                     // (Boolean), display table headings (th/td elements) in the <thead>
        footers: true,                      // (Boolean), display table footers (th/td elements) in the <tfoot>
        formats: ["xlsx", "csv", "txt"],     // (String[]), filetype(s) for the export
        fileName: "URL Analyzer" + " - " + $("#domain").text() + " - " + currentDT,                     // (id, String), filename for the downloaded file
        bootstrap: true,                    // (Boolean), style buttons using bootstrap
//      position: "top",                    // (top, bottom), position of the caption element relative to table
        ignoreRows: null,                   // (Number, Number[]), row indices to exclude from the exported file
        ignoreCols: null,                   // (Number, Number[]), column indices to exclude from the exported file
        ignoreCSS: ".tableexport-ignore"    // (selector, selector[]), selector(s) to exclude from the exported file
    });
    
    /* default class, content, and separator for each export type */

    /* Excel Open XML spreadsheet (.xlsx) */
    $.fn.tableExport.xlsx = {
        defaultClass: "xlsx",
        buttonContent: "Save All as xlsx",
        mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        fileExtension: ".xlsx"
    };

    /* Excel Binary spreadsheet (.xls) */
    $.fn.tableExport.xls = {
        defaultClass: "xls",
        buttonContent: "Save All as xls",
        separator: "\t",
        mimeType: "application/vnd.ms-excel",
        fileExtension: ".xls"
    };

    /* Comma Separated Values (.csv) */
    $.fn.tableExport.csv = {
        defaultClass: "csv",
        buttonContent: "Save All as csv",
        separator: ",",
        mimeType: "application/csv",
        fileExtension: ".csv"
    };

    /* Plain Text (.txt) */
    $.fn.tableExport.txt = {
        defaultClass: "txt",
        buttonContent: "Save All as txt",
        separator: "  ",
        mimeType: "text/plain",
        fileExtension: ".txt"
    };
    /* default charset encoding (UTF-8) */
    $.fn.tableExport.charset = "charset=utf-8";

    /* default filename if "id" attribute is set and undefined */
    $.fn.tableExport.defaultFileName = "URL Analyzer";

    /* default class to style buttons when not using bootstrap  */
    $.fn.tableExport.defaultButton = "button-default";

    /* bootstrap classes used to style and position the export buttons */
//    $.fn.tableExport.bootstrap = ["btn", "btn-default", "btn-toolbar"];

    /* row delimeter used in all filetypes */
    $.fn.tableExport.rowDel = "\r\n";
}

function safeURL(inUrl) {
    $('#frameLoader').prop("src", inUrl);
}

function sortTable(table, col, reverse) {
    var tb = table.tBodies[0], // use `<tbody>` to ignore `<thead>` and `<tfoot>` rows
        tr = Array.prototype.slice.call(tb.rows, 0), // put rows into array
        i;
    reverse = -((+reverse) || -1);
    tr = tr.sort(function (a, b) { // sort rows
        return reverse // `-1 *` if want opposite order
            * (a.cells[col].textContent.trim() // using `.textContent.trim()` for test
                .localeCompare(b.cells[col].textContent.trim())
               );
    });
    for(i = 0; i < tr.length; ++i) tb.appendChild(tr[i]); // append each row in order
}

function makeSortable(table) {
    var th = table.tHead, i;
    th && (th = th.rows[0]) && (th = th.cells);
    if (th) i = th.length;
    else return; // if no `<thead>` then do nothing
    while (--i >= 0) (function (i) {
        var dir = 1;
        th[i].addEventListener('click', function () {sortTable(table, i, (dir = 1 - dir))});
    }(i));
}

function makeAllSortable(parent) {
    parent = parent || document.body;
    var t = parent.getElementsByTagName('table'), i = t.length;
    while (--i >= 0) makeSortable(t[i]);
}

function adCall(domainToCheck) {
	//console.log("called ADS");
	var wr = [];
	for(var i = 0; i < domainToCheck.length; i++){
		if(wr.indexOf(domainToCheck[i]) == -1){
			wr.push(domainToCheck[i]);
		}
	}
	
	chrome.storage.local.get('bl', function(g) {
		if(g.length) {
			//console.log("bl: ", g);
			//console.log("bl: ", g.bl);
			//console.log("wr: ", wr);
			outerloop:
			for(var j = 0; j < wr.length; j++) {
				for(var k = 2998; k < g.bl.length; k++) {
					var z = (g.bl[k]).match(new RegExp('(.*)'+wr[j]+'/(.*)'));
					if (wr[j] && z) {
						//console.log("wr: ", wr[j]);
						//console.log("detected Ad: ", z);
						//console.log("flagAds: ", flagAds);
						if (flagAds == 0) {
							adsTag = "<span class='badge badge-primary'>" + 'Ads' + "</span>";
							$('#tagsDetected').append(adsTag);
							$('#tagsDetected').show();
							flagAds = 1;
						}
						//console.log("STOP!");
						break outerloop;
					}
				}
			}
		}
	});
}

function renderHeaderReq(r, ir) {
    //console.log("REQ: ", ir, r);
    var flagRef;
    //modal
    var modal3 = document.createElement('div');
    var modal2 = document.createElement('div');
    var modal1 = document.createElement('div');
    var modalHeader = document.createElement('div');
    var modalHeaderImg = document.createElement('img');
    var modalTitle = document.createElement('h4');
    var modalBody = document.createElement('div');
	var modalFooter = document.createElement('div');
	var btnClose = document.createElement('button');
    var br = document.createElement('br');
    var b = document.createElement('b');
    var headerReqTable = document.createElement('table');
    var headerReqTh = document.createElement('th');
    
    //modalHeaderImg.setAttribute('src','../detective.png');
    modalHeaderImg.setAttribute('aria-label','Close');
    
    modalTitle.innerText = "Web Request & Response Headers";

    headerReqTable.setAttribute('class','trafficTable');
    headerReqTh.setAttribute('colspan','2');
    headerReqTh.innerText = "Request Headers";
    headerReqTable.appendChild(headerReqTh);
    
    var reqHeaders = {};
    reqHeaders = r.requestHeaders;
    
    for (n=0; n < reqHeaders.length; n++) {
        var headerReqTr = document.createElement('tr');
        var headerReqTd1 = document.createElement('td');
        var headerReqTd2 = document.createElement('td');
        
        headerReqTd2.setAttribute("style","word-break: break-all;");
        headerReqTd1.innerText = reqHeaders[n].name;
        headerReqTd2.innerText = reqHeaders[n].value;
        
        headerReqTr.appendChild(headerReqTd1);
        headerReqTr.appendChild(headerReqTd2);
        headerReqTable.appendChild(headerReqTr);
        
        if (reqHeaders[n].name == "Content-Type") {
            cType = reqHeaders[n].value;
            cType = cType.split(';')[0];
        }
        
        if (reqHeaders[n].name == "Referer") {
            ref = reqHeaders[n].value;
            ori = r.url;
            
            var ul = document.createElement('ul');
            var li = document.createElement('li');
            li.setAttribute('id',"cc" + r.requestId);
            li.innerText = r.url;
            ul.appendChild(li);
            $('#callChain').append(ul);
            //console.log("drawn by loop:referrer:: ", r.url);
            flagRef = 1;
        }
    }
    
    if (flagRef != 1) {
        var li = document.createElement('li');
        li.setAttribute('id',"cc" + r.requestId);
        li.innerText = r.url;
        $('#callChain').append(li);
//      //console.log("drawn by NoReferrer", r.url);
    }
    
    headerReqTable.appendChild(modalHeader);
    
    modal3.setAttribute('id','m'+r.requestId);
    modal3.setAttribute('class','modal fade bs-example-modal-lg');
    modal3.setAttribute('tabindex','-1');
    modal3.setAttribute('role','dialog');
    modal3.setAttribute('aria-labelledby','myLargeModalLabel');
    modal2.setAttribute('class','modal-dialog modal-lg');
    modal2.setAttribute('role','document');
    modal1.setAttribute('class','modal-content');
    modalHeader.setAttribute('class','modal-header');
    modalTitle.setAttribute('class','modal-title');
    modalBody.setAttribute('class','modal-body');
    modalBody.setAttribute('id',"modal"+r.requestId);
	modalFooter.setAttribute('class','modal-footer');
    
	btnClose.setAttribute('type','button');
	btnClose.setAttribute('class','btn btn-secondary');
	btnClose.setAttribute('data-dismiss','modal');
	btnClose.innerText = "Close";
	modalFooter.appendChild(btnClose);
    
    modalHeader.appendChild(modalTitle);
	modalHeader.appendChild(modalHeaderImg);
    modal1.appendChild(modalHeader);

    modalBody.appendChild(br);
    modalBody.appendChild(br);
    modalBody.appendChild(headerReqTable);
    modalBody.appendChild(br);
    modalBody.appendChild(br);
    modal1.appendChild(modalBody);
	modal1.appendChild(modalFooter);
    modal2.appendChild(modal1);
    modal3.appendChild(modal2);
    $('#modal').append(modal3);
}

function renderHeaderResp(d, id) {
	urlToCheck.push({url: d.url, id: d.requestId});

    var type = d.type;
	var initiator = d.initiator;
	if (initiator == undefined) {
		initiator = "";
	}
		
	switch (type) {
		case "main_frame":
			if ($("#loadingModal span").length < 3) {
				$("#loadingModal .modal-body span").append("<br><span id='reqMethod'>Request Method: "+d.method+"</span><br><span>Status Code: "+d.statusLine+"</span><br><span>IP Address: "+d.ip+"</span>");
				if (!d.ip) {
					$("#ipAddr").text('&nbsp;');
				} else {
					$("#ipAddr").text(d.ip);
				}
			}
			break;
		case "xmlhttprequest":
			type = "XHR";
			if (flagXhr == 0) {
				xhrTag = "<span class='badge badge-primary'>" + 'XHR' + "</span>";
				$('#tagsDetected').append(xhrTag);
				$('#tagsDetected').show();
				flagXhr = 1;
			}
			break;
		case "websocket":
			type = "websocket";
			if (flagWebsocket == 0) {
				websocketTag = "<span class='badge badge-primary'>" + 'Websocket' + "</span>";
				$('#tagsDetected').append(websocketTag);
				$('#tagsDetected').show();
				flagWebsocket = 1;
			}
			break;
		case "sub_frame":
			type = "iframe";
			if (flagFrame == 0) {
				iframeTag = "<span class='badge badge-primary'>" + 'iframe' + "</span>";
				$('#tagsDetected').append(iframeTag);
				$('#tagsDetected').show();
				flagFrame = 1;
			}
			break;
		case "script":
			type = "script";
			if (flagScript == 0) {
				scriptTag = "<span class='badge badge-primary'>" + 'Script' + "</span>";
				$('#tagsDetected').append(scriptTag);
				$('#tagsDetected').show();
				flagScript = 1;
			}
			break;
		case "stylesheet":
			type = "stylesheet";
			if (flagStylesheet == 0) {
				stylesheetTag = "<span class='badge badge-primary'>" + 'Stylesheet' + "</span>";
				$('#tagsDetected').append(stylesheetTag);
				$('#tagsDetected').show();
				flagStylesheet = 1;
			}
			break;
		case "image":
			type = "image";
			if (flagImage == 0) {
				imageTag = "<span class='badge badge-primary'>" + 'Image' + "</span>";
				$('#tagsDetected').append(imageTag);
				$('#tagsDetected').show();
				flagImage = 1;
			}
			break;
		case "font":
			type = "font";
			if (flagFont == 0) {
				fontTag = "<span class='badge badge-primary'>" + 'Font' + "</span>";
				$('#tagsDetected').append(fontTag);
				$('#tagsDetected').show();
				flagFont = 1;
			}
			break;
		case "media":
			type = "media";
			if (flagMedia == 0) {
				mediaTag = "<span class='badge badge-primary'>" + 'Media' + "</span>";
				$('#tagsDetected').append(mediaTag);
				$('#tagsDetected').show();
				flagMedia = 1;
			}
			break;
		case "csp_report":
			type = "csp_report";
			if (flagCsp == 0) {
				cspTag = "<span class='badge badge-danger'>" + 'CSP Report' + "</span>";
				$('#tagsDetected').append(cspTag);
				$('#tagsDetected').show();
				flagCsp = 1;
			}
			break;
		case "object":
			type = "object";
			if (flagObject == 0) {
				objectTag = "<span class='badge badge-primary'>" + 'Object' + "</span>";
				$('#tagsDetected').append(objectTag);
				$('#tagsDetected').show();
				flagObject = 1;
			}
			break;
		case "ping":
			type = "ping";
			if (flagPing == 0) {
				pingTag = "<span class='badge badge-primary'>" + 'Beacon' + "</span>";
				$('#tagsDetected').append(pingTag);
				$('#tagsDetected').show();
				flagPing = 1;
			}
			break;
		default:
			break;
	}
    
    //"content-type"
    

    status = d.statusCode;
    
    
    var url = d.url;
    protocol = url.split(':')[0];
    hostname = url.split('//')[1];
    hostname = hostname.split('/')[0];
    
    var resHeaders = {};
    resHeaders = d.responseHeaders;
    
    //modal
    var headerGenTable = document.createElement('table');
    var headerGenTr1 = document.createElement('tr');
    var headerGenTr2 = document.createElement('tr');
    var headerGenTr3 = document.createElement('tr');
	var headerGenTr4 = document.createElement('tr');
	var headerGenTr5 = document.createElement('tr');
    
    var headerGenTd11 = document.createElement('td');
    var headerGenTd12 = document.createElement('td');
    var headerGenTd21 = document.createElement('td');
    var headerGenTd22 = document.createElement('td');
    var headerGenTd31 = document.createElement('td');
    var headerGenTd32 = document.createElement('td');
	var headerGenTd41 = document.createElement('td');
    var headerGenTd42 = document.createElement('td');
	var headerGenTd51 = document.createElement('td');
    var headerGenTd52 = document.createElement('td');
    
    var headerGenBr = document.createElement('br');
    
    headerGenTable.setAttribute('class','headerGenTable');
	headerGenTable.setAttribute('class','trafficTable');
    headerGenTd12.setAttribute('class','headerGenTableTd');
    headerGenTd22.setAttribute('class','headerGenTableTd');
    headerGenTd32.setAttribute('class','headerGenTableTd');
	headerGenTd42.setAttribute('class','headerGenTableTd');
	headerGenTd52.setAttribute('class','headerGenTableTd');
    
    headerGenTd11.innerText = "Request URL";
    headerGenTd12.innerText = url;
    headerGenTd21.innerText = "Request Method";
    headerGenTd22.innerText = d.method;
    headerGenTd31.innerText = "Status Code";
    headerGenTd32.innerText = d.statusLine;
	headerGenTd41.innerText = "IP Address";
    headerGenTd42.innerText = d.ip;
	headerGenTd51.innerText = "Referrer URL";
    headerGenTd52.innerText = initiator;
        
    headerGenTr1.appendChild(headerGenTd11);
    headerGenTr1.appendChild(headerGenTd12);
    headerGenTr2.appendChild(headerGenTd21);
    headerGenTr2.appendChild(headerGenTd22);
    headerGenTr3.appendChild(headerGenTd31);
    headerGenTr3.appendChild(headerGenTd32);
	headerGenTr4.appendChild(headerGenTd41);
	headerGenTr4.appendChild(headerGenTd42);
    headerGenTr5.appendChild(headerGenTd51);
    headerGenTr5.appendChild(headerGenTd52);
    headerGenTable.appendChild(headerGenTr1);
    headerGenTable.appendChild(headerGenTr2);
    headerGenTable.appendChild(headerGenTr3);
	headerGenTable.appendChild(headerGenTr4);
	headerGenTable.appendChild(headerGenTr5);
    
    headerGenTable.appendChild(headerGenBr);
    headerGenTable.appendChild(headerGenBr);
    
    $('#modal'+d.requestId).prepend(headerGenTable);
    
    var headerResTable = document.createElement('table');
    var headerResTh = document.createElement('th');
    headerResTable.setAttribute('class','trafficTable');
    headerResTh.setAttribute('colspan','2');
    headerResTh.innerText = "Response Headers";
    headerResTable.appendChild(headerResTh);
    
    for (n=0; n < resHeaders.length; n++) {
        var headerResTr = document.createElement('tr');
        var headerResTd1 = document.createElement('td');
        var headerResTd2 = document.createElement('td');
        
        headerResTd2.setAttribute("style","word-break: break-all;");
        headerResTd1.innerText = resHeaders[n].name;
        headerResTd2.innerText = resHeaders[n].value;
        
        headerResTr.appendChild(headerResTd1);
        headerResTr.appendChild(headerResTd2);
        headerResTable.appendChild(headerResTr);
        
        if (resHeaders[n].name == "Content-Type") {
            cType = resHeaders[n].value;
            cType = cType.split(';')[0];
        }
        
        if (resHeaders[n].name == "content-length") {
            cLen = resHeaders[n].value;
        }
        
        //console.log("id: ", d.parentFrameId);
        if ( (refusedToLoadOnFrame === "ALLOW") && (d.parentFrameId == '-1') && ((resHeaders[n].name == "X-Frame-Options") || (resHeaders[n].name == "x-frame-options"))) {
            if ((resHeaders[n].value == "DENY") || (resHeaders[n].value == "deny") || (resHeaders[n].value == "SAMEORIGIN") || (resHeaders[n].value == "sameorigin")) {
                refusedToLoadOnFrame = "DENY";
                
                var modal3 = document.createElement('div');
                var modal2 = document.createElement('div');
                var modal1 = document.createElement('div');
                var modalHeader = document.createElement('div');
                var modalHeadClose = document.createElement('button');
                var modalTitle = document.createElement('h4');
                var modalBody = document.createElement('div');
                var br = document.createElement('br');
                var p = document.createElement('p');
                
                modalHeadClose.setAttribute('type','button');
                modalHeadClose.setAttribute('class','close');
                modalHeadClose.setAttribute('data-dismiss','modal');
                modalHeadClose.setAttribute('aria-label','Close');
				modalHeadClose.setAttribute('data-backdrop','false');
                modalHeader.appendChild(modalHeadClose);

                modalTitle.innerText = "X-Frame-Options = 'DENY'";
                
                modal3.setAttribute('id', 'refusedToLoadOnFrameWrap');
                modal3.setAttribute('class','modal fade bs-example-modal-lg');
                modal3.setAttribute('tabindex','-1');
                modal3.setAttribute('role','dialog');
                modal3.setAttribute('aria-labelledby','myLargeModalLabel');
                modal2.setAttribute('class','modal-dialog');
                modal2.setAttribute('role','document');
                modal1.setAttribute('class','modal-content');
                modalHeader.setAttribute('class','modal-header');
                modalTitle.setAttribute('class','modal-title');
                modalBody.setAttribute('class','modal-body');
                modalBody.setAttribute('id','refusedToLoadOnFrame');

                modalHeader.appendChild(modalTitle);
                modal1.appendChild(modalHeader);
                p.innerText = "Heads Up! This URL couldn't load on frame window, but still you can track its components and live HTTP Headers by loading it on a new tab or window on a browser."
                modalBody.appendChild(br);
                modalBody.appendChild(br);
                modalBody.appendChild(p);
                modalBody.appendChild(br);
                modal1.appendChild(modalBody);
                modal2.appendChild(modal1);
                modal3.appendChild(modal2);
                $('#modal').append(modal3);
                $('#refusedToLoadOnFrameWrap').modal('show');
            }
        }
    }
    $('#modal'+d.requestId).append(headerResTable);
    
    var tbody = document.createElement('tbody');
    var tr = document.createElement('tr');
    var td1 = document.createElement('td');
    var td2 = document.createElement('td');
    var td3 = document.createElement('td');
    var td4 = document.createElement('td');
    var td5 = document.createElement('td');
    var td6 = document.createElement('td');
    var td7 = document.createElement('td');
	var td8 = document.createElement('td');
//    var icoDiv = document.createElement('span');
	var span6 = document.createElement('span');
	var span7 = document.createElement('span');
    var span8 = document.createElement('span');
//    var ico = document.createElement('span');
    
    tr.setAttribute("class", "iURL");
    tr.setAttribute('title',"Click here to read its HTTP Headers");

    tr.setAttribute("data-toggle", "modal");
    tr.setAttribute("data-target", "#m"+d.requestId);
	tr.setAttribute("id", d.requestId);

	span6.setAttribute("style","display:inline-block;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;max-width:12em");
	span7.setAttribute("style","display:inline-block;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;max-width:12em");
	span8.setAttribute("style","display:inline-block;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;max-width:49em");
    td8.setAttribute("class","divURL");
	td8.setAttribute("data-toggle","tooltip");
	td8.setAttribute("data-placement","left");
	td8.setAttribute("data-original-title",url);

    td1.innerText = d.requestId;
    td2.innerText = status;
    
    if (cLen == undefined) {
        cLen = '';
    } else {
        td3.setAttribute('title', cLen + ' bytes');
    }
    
    if (cType == undefined) {
        cType = type;
    }
    
    td3.innerText = cLen;
    td4.innerText = cType;
    td5.innerText = '';
	if (d.initiator) {
		var ini = d.initiator.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
		span6.innerText = ini;
	} else {
		var ini = "";
		span6.innerText = "";
	}
    span7.innerText = hostname;
    span8.innerText = url;

    var dListExist = domainslist.indexOf(hostname);
    if (dListExist == '-1') {
        domainslist.push(hostname);
        $('#dList').append(hostname+"<br>");
    }
	
    if ((status == 301) || (status == 302) || (status == 303)) {
        if (flagRedirect == 0) {
            $('#tagsDetected').show();
            redirectTag = "<span class='badge badge-primary'>" + 'Redirect' + "</span>";
            $('#tagsDetected').append(redirectTag);
            flagRedirect = 1;
        }
        
        var span1 = document.createElement('span');
        span1.setAttribute("class", 'redirect');
        span1.innerText = 'Redirect';
        td5.appendChild(span1);
    }
    
    if (status == 400) {
        if (flagBadRequest == 0) {
            $('#tagsDetected').css('display','block');
            badRequestTag = "<span class='badge badge-primary'>" + status + " Bad Request</span>";
            $('#tagsDetected').append(badRequestTag);
            flagBadRequest = 1;
        }
        
        var span0 = document.createElement('span');
        span0.setAttribute("class", 'badrequest');
        span0.innerText = status;
        td5.appendChild(span0);
    }
    
    if (status == 404) {
        if (flagNotFound == 0) {
            $('#tagsDetected').css('display','block');
            notFoundTag = "<span class='badge badge-primary'>" + status + " Not Found</span>";
            $('#tagsDetected').append(notFoundTag);
            flagNotFound = 1;
        }
        
        var span0 = document.createElement('span');
        span0.setAttribute("class", 'notfound');
        span0.innerText = status;
        td5.appendChild(span0);
    }
    
    if (protocol == 'http') {
        if (flagNonSSL == 0) {
            $('#tagsDetected').css('display','block');
            nonsslTag = "<span class='badge badge-danger'>Non-secure</span>";
            $("#tagsDetected").append(nonsslTag);
            flagNonSSL = 1;
        }
        
        var span2 = document.createElement('span');
        span2.setAttribute("class", 'nonssl');
        span2.innerText = protocol;
        td5.appendChild(span2);
    }
    
    var mediaSWF = url.match(/.swf/gi);
    
    if (mediaSWF == '.swf') {
        //console.log(mediaSWF);
        if (flagFlash == 0) {
            $('#tagsDetected').css('display','block');
            flashTag = "<span class='badge badge-primary'>" + 'Flash' + "</span>";
            $("#tagsDetected").append(flashTag);
            flagFlash = 1;
        }
        var span3 = document.createElement('span');
        span3.setAttribute("class", 'flash');
        span3.innerText = 'Flash';
        td5.appendChild(span3);
    }
    
    if ((url.match(/.nsv/gi)) || (url.match(/.mp4/gi)) || (url.match(/.m4v/gi)) || (url.match(/.mpg/gi)) || (url.match(/.flv/gi)) || (url.match(/.webm/gi))) {
        if (flagVideo == 0) {
            $('#tagsDetected').css('display','block');
            videoTag = "<span class='badge badge-primary'>" + 'Video' + "</span>";
            $("#tagsDetected").append(videoTag);
            flagVideo = 1;
        }
        var span4 = document.createElement('span');
        span4.setAttribute("class", 'video');
        span4.innerText = 'Video';
        td5.appendChild(span4);
    }
	
	domainToCheck.push(hostname);
	   
    tr.appendChild(td1);
    tr.appendChild(td2);
    tr.appendChild(td3);
    tr.appendChild(td4);
    tr.appendChild(td5);
    
	td6.appendChild(span6);
	tr.appendChild(td6);
	td7.appendChild(span7);
	tr.appendChild(td7);

    td8.appendChild(span8);
    tr.appendChild(td8);
    
    $('#tbody').append(tr);
}

function others() {
	$('#ctTab').attr("style","cursor:pointer");
	$('#ctTab a:first').tab('show');
	
	chrome.runtime.onMessage.addListener(function(get) {
		if(get.type == "wrq") {
		  //console.log("wrq content: ", get.content);
				ir++;
			  renderHeaderReq(get.content,ir);
		}
		  if(get.type == "wrp") {
		  //console.log("wrp content: ", get.content);
			  id++;
			  renderHeaderResp(get.content,id);
		}
		return true;
	  });
    var inURL, btnFrame = $('#btnFrame');
    $('#inputFrame').keypress(function(e) {
        if(e.which == 13) {
            $('#tagsDetected').children().remove(); // clear tagsDetected
            $('#tagsDetected').css('display','none'); //hide tagsDiv
            flagRedirect = flagBadRequest = flagNotFound = flagNonSSL = flagFlash = flagVideo = 0;
            $('#liveTraffic caption').remove(); // clear export buttons
            $('#exportWrap').css('display','block');
            $('#liveTraffic tbody').children().remove(); //clear liveTraffic table
            $('#callChain').children().remove(); //clear callChain
            $('#dList').children().remove(); //clear domain list
            $('#inputFrame').css('cursor','wait');
            $('#inputFrame').prop('disabled', true);
            refusedToLoadOnFrame = "ALLOW";
            
            inURL = $('#inputFrame').val();
            if (inURL !== '' || inURL !== undefined) {
                safeURL(inURL);
            } else {
                alert("Entered input is invalid! Try again.");
            }

            var animateIconClass = "iconLoadAnimate", icoLoad = $('#urlLoadIco');
            icoLoad.removeClass('glyphicon glyphicon-globe');
            icoLoad.addClass('glyphicon glyphicon-refresh');
            icoLoad.addClass(animateIconClass);
            
            // Get iframe html source code
            $.ajax({
                url: $("iframe#frameLoader").attr("src"),
                type: 'GET',
				async: true,
                dataType: 'html'
            }).done(function(html) {
                //console.log(html);
                icoLoad.removeClass(animateIconClass);
                icoLoad.removeClass('glyphicon glyphicon-refresh');
                icoLoad.addClass('glyphicon glyphicon-globe');
                $('#inputFrame').css('cursor','text');
                $('#inputFrame').prop('disabled', false);
                
                $('#srcCodePre').text(html);
                $('pre#srcCodePre').litelighter({
                    style: 'dark',
                    language: 'html'
                });
                $('#srcCodePre').css('min-height','600px');
                $('#srcCodePre').css('word-break','break-all');
                $('#srcCodePre').css('word-wrap','break-word');
                $('#srcCodePre').css('white-space','pre');
                $('#srcCodePre').css('white-space','-moz-pre-wrap');
                $('#srcCodePre').css('white-space','pre-wrap');
                $('#srcCodePre').css('white-space','pre\9');
            });          
            
        }
    });

    
    $('.divURL').mouseover(function () {
       $(this).children('span:first').css("visibility","visible");
    });
    
    $('.divURL').mouseleave(function () {
       $(this).children('span:first').css("visibility","hidden");
    });
        
    makeAllSortable();
    
    $('#liveTrafficContainer').find('a:last').remove();
    $('#liveTrafficContainer').find('a:last').remove();

    $('[data-toggle="tooltipExport"]').hover(function(){
            $('#exportIcon').popover('show');
        setTimeout(function() {
            $('.popover').fadeOut('slow',function() {}); 
        },5000);
    });
    
    $('ul.tree li:last-child').addClass('last');
    
    // scrollup div
    var isVisible = false;
    $('#scrollup').click(function(){
        $('html, body').animate({
        scrollTop: $('body').offset().top
        }, 'slow');
    });
    $(window).scroll(function(){
         var shouldBeVisible = $(window).scrollTop()>500;
         if (shouldBeVisible && !isVisible) {
              isVisible = true;
              $('#scrollup').show(1000);
         } else if (isVisible && !shouldBeVisible) {
              isVisible = false;
              $('#scrollup').hide(1000);
        }
    });
    
//    chkIncognitoMode();
	
	//live traffic table search
	$("#liveNetworkTrafficSearch").on("keyup", function() {
		var value = this.value.toLowerCase().trim();
		$("table tr").each(function (index) {
			if (!index) return;
			$(this).find("td").each(function () {
				var id = $(this).text().toLowerCase().trim();
				var not_found = (id.indexOf(value) == -1);
				$(this).closest('tr').toggle(!not_found);
				return not_found;
			});
		});
	});
	$("#tabIcon").attr("src","detective.png");
	
	$("#ctTab li").on("click", function(){
	   $("nav").find(".active").removeClass("active");
	   $(this).addClass("active");
	});
	
	$("#header-privacy").click(function() {
		$("#ppModal").modal("show");
	});
	
	$("#header-info").click(function() {
		$("#chlogModal").modal("show");
	});
	
	setTimeout(function() {
		$(".button-container").css("transition","all 0.6s ease-out");
		$(".button-container").css("opacity","1");
		//console.log("called GSB");
		gsb(urlToCheck);
		adCall(domainToCheck);
	//	phishtank(url);
		try {
			dListGraph();

			if($("#dList").text().match("google-analytics.com")!= null){
				var ga = $("#dList").text().match("google-analytics.com")[0];
				if (ga !== null) {
					if (flagAnaly == 0) {
						analyTag = "<span class='badge badge-primary'>" + 'Analytics' + "</span>";
						$('#tagsDetected').append(analyTag);
						$('#tagsDetected').show();
						flagAnaly = 1;
					}
				}
			}
		}
		catch(err) {
			//console.log(err);
		}
	}, 9000);

	setTimeout(function() {
		$("#domains-list h5 div")[0].append(domainslist.length);
		var intPgLinksTotal = $('#https-links li').length + $('#http-links li').length;
		var extPgLinksTotal = $('#external-links li').length;
		$("#intDiv h5 div")[0].append(intPgLinksTotal);
		$("#extDiv h5 div")[0].append(extPgLinksTotal);
		$("#safeFrame").css("width","100%");
		$("#safeFrame").css("height","100vh");
		$("#loadingModal").modal("hide");
		//_gaq.push(['_trackEvent', 'URL Inspect', 'success', 'URL Inspect']);
		$('[data-toggle="tooltip"]').tooltip(); //tooltip
	}, 16000);
}

function openNewTab(url) {
	chrome.tabs.create({
		url: url,
		active: false
	}, function(t) {
		//console.log(t);
		chrome.runtime.sendMessage({content: [t.id,url], type: "openerTabId"});
	});
}

function atools(d,url) {
	whois(d);
	ads(d);
	appAds(d);
	extractLinks(url);
	subdomain(d);
	dns(d); // need update
	pgArchive(url);
	geoIP(d);
	domainReputation(d);
	robots(d);
	cookies(d);
}

function urlInputValidation() {
	$('#url-submit').click(function () {
		url = $('#url-input').val();
		if (url.length != 0) {
			var urlregex = new RegExp("[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)+.*");
  			var validateURL = urlregex.test(url);
			//console.log("Valid input? ", validateURL);
			if (validateURL == true) {
				d = url.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
				//console.log("url: ", url);
				//console.log("d: ", d);
				$(".url").text(url);
				$("#domain").text(d);
				notification();
				others();
				openNewTab(url);
				atools(d,url);
				$("#home").css("display","none");
				$("#scanResults").css("display","block");
			} else {
                $('#url-input').val("");
				$("#notifyinfo").text("You have entered an invalid input!");
				$("#notifyinfo").addClass("show");
				setTimeout(function(){ $("#notifyinfo").removeClass("show"); }, 3000);
			}
		} else {
			$("#notifyinfo").text("You have entered an invalid input!");
			$("#notifyinfo").addClass("show");
			setTimeout(function(){ $("#notifyinfo").removeClass("show"); }, 3000);
		}
	});
	
	$('#url-input').keypress(function(e) {
		if(e.which == 13) {
			url = $('#url-input').val();
			if (url.length != 0) {
				var urlregex = new RegExp("[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)+.*");
				var validateURL = urlregex.test(url);
				console.log("Valid input? ", validateURL);
				if (validateURL == true) {
					d = url.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
					$('.url').text(url);
					$('#domain').text(d);
					notification();
					others();
					openNewTab(url);
					atools(d,url);
					$("#home").css("display","none");
					$("#scanResults").css("display","block");
				} else {
					$('#url-input').val("");
					$("#notifyinfo").text("You have entered an invalid input!");
					$("#notifyinfo").addClass("show");
					setTimeout(function(){ $("#notifyinfo").removeClass("show"); }, 3000);
				}
			} else {
				$("#notifyinfo").text("You have entered an invalid input!");
				$("#notifyinfo").addClass("show");
				setTimeout(function(){ $("#notifyinfo").removeClass("show"); }, 3000);
			}
		}
	});
}

//isOnline
function updateOnlineStatus(event) {
	var isOnline = $('#isOnline');
	var condition = navigator.onLine ? "online" : "offline";
	if (condition == 'online') {
		isOnline.removeClass('offline');
		isOnline.addClass('online');
		isOnline.text("Back " + condition.toUpperCase());
		setTimeout(function(){$('#isOnline').css('display','none');}, 6000);
	} else {	
		isOnline.css('display','block');
		isOnline.removeClass('online');
		isOnline.addClass('offline');
		isOnline.text(condition.toUpperCase() + "! Please check your internet connection.");
	}
}

function startInspect(){
	window.addEventListener('online', updateOnlineStatus);
	window.addEventListener('offline', updateOnlineStatus);
	
	$("body").delay(50).animate({"opacity": "1"}, 100);
    $("body").on("contextmenu",function(e){
		return true;
	});
	var url = getUrlParameter('url');
	var ref = getUrlParameter('r');

//	console.log(ref,url);
	if(ref){
		if(ref == "context-menu"){
			notification();
			others();
			$('.url').text(url);
			d = url.replace('http://','').replace('https://','').replace('www.','').split(/[/?#]/)[0];
			$('#domain').text(d);
			$('#safeFrame').attr("src", url);
			atools(d,url);
		} else {
			$("#home").css("display","flex");
			urlInputValidation();
		}
	} else {
		$("#home").css("display","flex");
		urlInputValidation();
	}
	
	$("#tabToXlsx").click(function () {
		$("#liveNetworkTraffic").table2excel({
			filename: d + " - " + new Date().toISOString().replace(/[\-\:\.]/g, "") + ".xls"
		});
		$("#snackbar").text("Note: You may see an alert while opening this file as corrupted or unsafe, however, it is safe to continue by click \"yes\" and will fix this in future updates.");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
		//_gaq.push(['_trackEvent', 'Download', 'success', 'Network']);
	});
	
	$(".trigger").click(function() {
		$(".menu").toggleClass("active");
	});
	
	$(".rotater:nth-child(1)").click(function(e) {
		$("#ctTab li").removeClass('active');
		$("#ctTab li a").removeClass('active');
		$("#ctTab a[href='#url-components']").tab('show');
    	e.preventDefault();
	});
	
	$(".rotater:nth-child(2)").click(function(e) {
		$("#ctTab").removeClass('active');
		$("#ctTab a").removeClass('active');
		$("#ctTab a[href='#domain-graph']").tab('show');
    	e.preventDefault();
	});
	
	$(".rotater:nth-child(3)").click(function(e) {
		$("#ctTab").removeClass('active');
		$("#ctTab a").removeClass('active');
		$("#ctTab a[href='#safe-frame']").tab('show');
    	e.preventDefault();
	});
	
	$(".rotater:nth-child(4)").click(function(e) {
		$("#ctTab").removeClass('active');
		$("#ctTab a").removeClass('active');
		$("#ctTab a[href='#domains-list']").tab('show');
    	e.preventDefault();
	});
	
	$(".rotater:nth-child(5)").click(function(e) {
		$("#ctTab").removeClass('active');
		$("#ctTab a").removeClass('active');
		$("#ctTab a[href='#page-links']").tab('show');
    	e.preventDefault();
	});
	
	$("#saveBtnPgSrc").click(function() {
		saveAsTxt("Page Source");
	});

	$("#saveBtnWhois").click(function() {
		saveAsTxt("Whois Lookup");
	});
	
	$("#saveBtnDlist").click(function() {
		saveAsTxt("Extracted domain list");
	});
	
	$("#saveBtnPgLinks").click(function() {
		saveAsTxt("Page Links");
	});
	
	$("#saveBtnDNS").click(function() {
		saveAsTxt("DNS Lookup");
	});
	
	$("#saveBtnSD").click(function() {
		saveAsTxt("Subdomain");
	});

	$("#saveBtnGeoIP").click(function() {
		saveAsTxt("Geo-IP Lookup");
	});
	
	$("#saveBtnAds").click(function() {
		saveAsTxt("Authorized Digital Sellers");
	});
	
	$("#saveBtnSS").click(function() {
		saveAsTxt("Screenshot");
	});
	
	$("#saveBtnReputation").click(function() {
		saveAsTxt("Domain Reputation");
	});
	
	$("#saveBtnCrawlers").click(function() {
		saveAsTxt("Crawlers");
	});
	
	$("#copyBtnPgSrc").click(function() {
		copyToClipboard('#srcCodePre');
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'Page Source']);
		$("#snackbar").text("The page source has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnWhois").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'Whois']);
		copyToClipboard('#whois pre');
		$("#snackbar").text("The whois lookup result has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnSD").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'Subdomain']);
		copyToClipboard('#subDomainResults');
		$("#snackbar").text("The subdomain has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnDNS").on('click',function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'DNS']);
		copyToClipboard('#fdns pre');
		$("#snackbar").text("The DNS lookup result has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnDlist").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'Domain List']);
		copyToClipboard('#dList');
		$("#snackbar").text("The extracted domain list has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnPgLinks").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'Page Links']);
		copyToClipboard('#https-links');
		$("#snackbar").text("The page links has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnGeoIP").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'GeoIP']);
		copyToClipboard('#geo-ip-location');
		$("#snackbar").text("The geo-IP result has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnAds").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'ads.txt']);
		copyToClipboard('#ads .card-text');
		$("#snackbar").text("The authorized digital sellers has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnReputation").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'Reputation']);
		copyToClipboard('#urlReputation');
		$("#snackbar").text("The domain reputation has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});
	
	$("#copyBtnCrawlers").click(function() {
		//_gaq.push(['_trackEvent', 'Copy', 'success', 'robots.txt']);
		copyToClipboard('#webCrawlers .card-text');
		$("#snackbar").text("The robots.txt details has been copied");
		$("#snackbar").addClass("show");
		setTimeout(function(){ $("#snackbar").removeClass("show"); }, 3000);
	});

//	inputMenu
	$("#inputMenu li").on("click", function() {
		$('#inputMenu ul.nav li.active').removeClass('active');
		$(this).addClass('active');
	});

	$("#submit_api").on("click", function() {
		saveKeys();
	});

	$("#toggleAPI").on("click",function(){
		$('#api_div').toggle();		
	});

	
}

function saveKeys(){
	gmapskey = $('#gmapskey').val();
	domainRep = $('#whoisxmlapi').val();
	phishTank = $('#phishTank').val();
	safeBrowse = $('#safeBrowse').val();
	hackerTarget = $('#hackerTarget').val();
	var _keys = [gmapskey,domainRep,phishTank,safeBrowse, hackerTarget]
	localStorage.setItem("keys", JSON.stringify(_keys));
}

function loadKeys(){

	var storedKeys = JSON.parse(localStorage.getItem("keys"));
	if(storedKeys){
		gmapskey = storedKeys[0];
		domainRep = storedKeys[1];
		phishTank = storedKeys[2];
		safeBrowse = storedKeys[3];
		hackerTarget = storedKeys[4];
	} else {
		gmapskey = '';
		domainRep = ''; 
		phishTank = '';
		safeBrowse = '';
		hackerTarget = '';
	}

	$('#gmapskey').val(gmapskey);
	$('#whoisxmlapi').val(domainRep);
	$('#phishTank').val(phishTank);
	$('#safeBrowse').val(safeBrowse);
	$('#hackerTarget').val(hackerTarget);

	startInspect();
}

$(document).ready(function() {
	loadKeys();
});

$(document).ajaxStop(function(){
 	//console.log("PAGE LOADED!");
});
