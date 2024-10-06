import googlemaps
from django.conf import settings

def calculate_distance(origin, destination):
    gmaps = googlemaps.Client(key=settings.GOOGLE_MAPS_API_KEY)
    
    try:
        result = gmaps.distance_matrix(origin, destination, mode="driving")
        distance = result["rows"][0]["elements"][0]["distance"]["value"] / 1000  # Convert to km
        return distance
    except Exception as e:
        print(f"Error calculating distance: {str(e)}")
        return None