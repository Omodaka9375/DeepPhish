var background = chrome.extension.getBackgroundPage();

function test_model() {
  $.getJSON("js/classifier.json", function(clfdata) {
    var rf = random_forest(clfdata);
    $.getJSON("js/testdata.json", function(testdata) {
      var X = testdata['X_test'];
      var y = testdata['y_test'];
      for(var x in X) {
        for(var i in x) {
          x[i] = parseInt(x[i]);
        }
      }
      var pred = rf.predict(X);
      var TP = 0, TN = 0, FP = 0, FN = 0;
      for(var i in pred) {
        if(pred[i][0] == true && y[i] == "1") {
          TP++;
        } else if(pred[i][0] == false && y[i] == "1") {
          FN++;
        } else if(pred[i][0] == false && y[i] == "-1") {
          TN++;
        } else if(pred[i][0] == true && y[i] == "-1") {
          FP++;
        }
      }
      var precision = TP/(TP+FP);
      var recall = TP/(TP+FN);
      var f1 = 2 * precision * recall / (precision + recall);
      $('#precision').text(precision);
      $('#recall').text(recall);
      $('#accuracy').text(f1);
    });
  });

  
}

test_model();

$('body').ready(function(){

  $('#dndcheck').prop('checked', background.getDnD());
  background.toggleIcon();

  $(document).on('change', '#dndcheck', function(){
    var isChecked = $('#dndcheck').is(':checked');
    console.log('Is checked state: ' + isChecked);
    if (!isChecked) {
      console.log('Its checked, unchecking')
      background.setDnD('false');
      background.toggleIcon();
      console.log(background.dnd);
    } else {
      console.log('Its unchecked, checking')
      background.setDnD('true');
      background.toggleIcon();
      console.log(background.dnd);
    }
  });
});