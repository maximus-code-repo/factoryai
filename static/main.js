// LogSentinel - drag & drop support for the upload zone.
document.addEventListener("DOMContentLoaded", function () {
  var zone = document.getElementById("dropzone");
  if (!zone) return;
  var input = zone.querySelector("input[type=" + "file]");
  var label = zone.querySelector(".dz-big");

  zone.addEventListener("click", function (e) {
    if (e.target !== input) input.click();
  });

  input.addEventListener("change", function () {
    if (input.files.length) {
      label.textContent = input.files[0].name;
    }
  });

  ["dragenter", "dragover"].forEach(function (ev) {
    zone.addEventListener(ev, function (e) {
      e.preventDefault();
      zone.classList.add("dragging");
    });
  });

  ["dragleave", "drop"].forEach(function (ev) {
    zone.addEventListener(ev, function (e) {
      e.preventDefault();
      zone.classList.remove("dragging");
    });
  });

  zone.addEventListener("drop", function (e) {
    if (e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event("change"));
    }
  });
});
