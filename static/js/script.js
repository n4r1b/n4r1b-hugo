var height = 350

if (
  document.readyState === "complete" ||
    (document.readyState !== "loading" && !document.documentElement.doScroll)
) {
  makeCollapsible();
} else {
  document.addEventListener("DOMContentLoaded", makeCollapsible);
}

function toggle(e) {
  e.preventDefault();
  var link = e.target;
  var div = link.parentElement.parentElement;

  if (div.className == "highlight-wrapper") {
    if (link.innerHTML === "Show More") {
      link.innerHTML = "Show Less";
      div.style.maxHeight = "";
      div.style.overflow = "none";
      link.parentElement.style.background = "none";
      link.parentElement.style.bottom = "5px";
    }
    else {
      link.innerHTML = "Show More";
      div.style.maxHeight = height.toString()+"px";
      div.style.overflow = "hidden";
      link.parentElement.style.bottom = "";
      link.parentElement.style.background = "linear-gradient(rgba(237,245,251,0),#2d2d2ded 30%)";
      div.scrollIntoView({ behavior: 'smooth',  block: "nearest" });
    }
  }
}

function makeCollapsible() {
  var divs = document.querySelectorAll('.highlight-wrapper');

  for (i=0; i < divs.length; i++) {
    var div = divs[i];
    if (div.offsetHeight > height) {
      div.style.maxHeight = height.toString()+"px";
      div.style.overflow = "hidden";

      if (div.childElementCount > 0 ) {
        var child = div.children[0];
        child.style.margin = "0px auto";

        if ( child.childElementCount > 0) {
          child.children[0].style.marginTop = "0px";
          child.children[0].style.marginBottom = "0px";
        }
      }

      var e = document.createElement('div');
      e.className = "highlight-link";

      var html = '<a href="">Show More</a>';
      e.innerHTML = html;
      
      div.appendChild(e);
    }
  }

  var links = document.querySelectorAll('.highlight-link');
  for (i=0; i<links.length; i++) {
    var link = links[i];
    link.addEventListener('click', toggle);
  }
}