// !fiab: bouton « Copier » et confirmation des actions sensibles (aucun script inline, CSP stricte)
document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-copy]");
  if (!button) return;
  var input = document.querySelector(button.dataset.copy);
  var done = function () {
    var label = button.textContent;
    button.textContent = "Copié";
    setTimeout(function () { button.textContent = label; }, 1500);
  };
  if (navigator.clipboard) {
    navigator.clipboard.writeText(input.value).then(done);
  } else {
    input.select();
    document.execCommand("copy");
    done();
  }
});

document.addEventListener("submit", function (event) {
  var message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
