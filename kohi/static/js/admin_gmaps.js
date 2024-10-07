
function initMap() {
    // This function will be called when the Google Maps API is fully loaded
    console.log("Google Maps API initialized");
}

document.addEventListener("DOMContentLoaded", function() {
    function initialize() {
        const addressField = document.getElementById('id_address');
        const latitudeField = document.getElementById('id_latitude');
        const longitudeField = document.getElementById('id_longitude');
        
        if (addressField) {
            const autocomplete = new google.maps.places.Autocomplete(addressField);
            autocomplete.addListener('place_changed', function () {
                const place = autocomplete.getPlace();
                if (!place.geometry) {
                    console.warn("No geometry available for the selected place");
                    return;
                }
                // Set latitude and longitude
                latitudeField.value = place.geometry.location.lat();
                longitudeField.value = place.geometry.location.lng();
            });
        } else {
            console.error("Address field not found!");
        }
    }

    // Check if Google Maps API is loaded
    if (typeof google !== 'undefined' && google.maps) {
        initialize();
    } else {
        console.error("Google Maps API not loaded properly.");
    }
});