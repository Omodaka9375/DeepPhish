var background = chrome.extension.getBackgroundPage();

var colors = {
    "-1": "rgb(67 203 80)", 
    "0": "#f9e004",
    "1":"#f93c3c"
};

var featureList = document.getElementById("features");
var exUrl = '';
chrome.tabs.query({ currentWindow: true, active: true }, function(tabs){
    var url = tabs[0].url;
    exUrl = tabs[0].url;
    if (url == "" || url == undefined || url == "chrome:" || url == "chrome://newtab/" || url == "chrome-extension:" || url == "chrome-plugins:" || url == "chrome-apps:" || url == "chrome-themes:" || url == "chrome-games:" || url == "edge:" || url == "edge://newtab/" || url == "edge://newtab" || url == "edge-extension:" || url == "edge://extensions" || url == "edge-plugins:" || url == "edge-apps:" || url == "edge-themes:" || url == "edge-games:" || url == "about:addons" || url == "about:debugging" || url == "moz-extension:" || url == "about:" || url == "about:newtab") {
        background.openNew();
    } else {
        $('#site_msg').text(url);
        var result = background.results[tabs[0].id];
        var isPhish = background.isPhish[tabs[0].id];
        var legitimatePercent = background.legitimatePercents[tabs[0].id];
 
        for(var key in result){
            var newFeature = document.createElement("li");
            newFeature.textContent = key;
            newFeature.style.backgroundColor=colors[result[key]];
            featureList.appendChild(newFeature);
        }
        
        $("#site_score").text(parseInt(legitimatePercent));
        if(isPhish) {
            $("#res-circle").css("background", "#FAD961");
            $("#res-circle").css("backgroundImage", "linear-gradient(90deg, #FAD961 0%, #F76B1C 100%)");
            //$("#site_score").text(parseInt(legitimatePercent)-20);
        }

        // get if #warn should shown
        if(isPhish){
            $('#warn').show();
        } else {
            $('#warn').hide();
        }
        // set checkbox state based on background.isMuted(url)
        if(background.isMuted(url)){
            console.log('Its muted ' + url)
            $('#ignoreUrl').prop('checked', true);
        } else {
            console.log('Its unmuted'+ url)
            $('#ignoreUrl').prop('checked', false);
        }

        //setIndicator
        var indices = background.getIndexesForSite(url);
        console.log(indices)
        //set state form indices array
        if(indices.length == 0){
            return;
        } else if (indices.length == 1){
            return;
        } else {
            if(indices[indices.length-1] > indices[indices.length-2]){
                $('.arrow-up').show();
                $('.arrow-down').hide();
            } else if (indices[indices.length-1] < indices[indices.length-2]){
                $('.arrow-down').show();
                $('.arrow-up').hide();
            } else {
                $('.arrow-down').hide();
                $('.arrow-up').hide();
            }
        }

    }
});

$(document).ready(function() {
    $("#ignoreUrl").on("click", function() {
		if($(this).is(':checked')){
            console.log('checked')
            // remove from muted websites
            background.addToMuted(exUrl);
            
        } else {
            //add to muted websites
            console.log('unchecked');
            background.removeFromMuted(exUrl);
        }
	});
});




