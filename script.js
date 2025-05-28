// Script for navigation bar
const bar =  document.getElementById('bar');
const nav = document.getElementsById('navbar');
if (bar) {
    bar.addEventListener('click', () => {
        nav.classListadd('active');
    })
}

