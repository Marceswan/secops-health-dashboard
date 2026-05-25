/**
 * Approximate geolocation lookup for country-coded login signals.
 *
 * Maps ISO-3166-1 alpha-2 country codes to a representative centroid
 * (latitude, longitude) and computes rough great-circle distance between
 * two countries. This is intentionally coarse: the impossible-travel rule
 * only needs km-scale separation to decide if two logins are physically
 * implausible, not survey-grade accuracy.
 *
 * Hardcoded map avoids a static resource round trip during detection.
 */
public with sharing class LoginGeoLookup {
    /** Mean Earth radius in kilometers. */
    private static final Double EARTH_RADIUS_KM = 6371.0;

    /**
     * Country centroid: lat at index 0, lon at index 1.
     * Covers the most common Salesforce login source countries.
     */
    private static final Map<String, List<Double>> CENTROIDS = new Map<String, List<Double>>{
        'US' => new List<Double>{ 39.8283, -98.5795 },
        'CA' => new List<Double>{ 56.1304, -106.3468 },
        'MX' => new List<Double>{ 23.6345, -102.5528 },
        'BR' => new List<Double>{ -14.2350, -51.9253 },
        'AR' => new List<Double>{ -38.4161, -63.6167 },
        'GB' => new List<Double>{ 55.3781, -3.4360 },
        'IE' => new List<Double>{ 53.1424, -7.6921 },
        'FR' => new List<Double>{ 46.2276, 2.2137 },
        'DE' => new List<Double>{ 51.1657, 10.4515 },
        'ES' => new List<Double>{ 40.4637, -3.7492 },
        'IT' => new List<Double>{ 41.8719, 12.5674 },
        'NL' => new List<Double>{ 52.1326, 5.2913 },
        'BE' => new List<Double>{ 50.5039, 4.4699 },
        'CH' => new List<Double>{ 46.8182, 8.2275 },
        'AT' => new List<Double>{ 47.5162, 14.5501 },
        'SE' => new List<Double>{ 60.1282, 18.6435 },
        'NO' => new List<Double>{ 60.4720, 8.4689 },
        'FI' => new List<Double>{ 61.9241, 25.7482 },
        'DK' => new List<Double>{ 56.2639, 9.5018 },
        'PL' => new List<Double>{ 51.9194, 19.1451 },
        'PT' => new List<Double>{ 39.3999, -8.2245 },
        'GR' => new List<Double>{ 39.0742, 21.8243 },
        'RU' => new List<Double>{ 61.5240, 105.3188 },
        'TR' => new List<Double>{ 38.9637, 35.2433 },
        'IL' => new List<Double>{ 31.0461, 34.8516 },
        'AE' => new List<Double>{ 23.4241, 53.8478 },
        'SA' => new List<Double>{ 23.8859, 45.0792 },
        'IN' => new List<Double>{ 20.5937, 78.9629 },
        'PK' => new List<Double>{ 30.3753, 69.3451 },
        'BD' => new List<Double>{ 23.6850, 90.3563 },
        'CN' => new List<Double>{ 35.8617, 104.1954 },
        'JP' => new List<Double>{ 36.2048, 138.2529 },
        'KR' => new List<Double>{ 35.9078, 127.7669 },
        'TW' => new List<Double>{ 23.6978, 120.9605 },
        'HK' => new List<Double>{ 22.3193, 114.1694 },
        'SG' => new List<Double>{ 1.3521, 103.8198 },
        'MY' => new List<Double>{ 4.2105, 101.9758 },
        'TH' => new List<Double>{ 15.8700, 100.9925 },
        'VN' => new List<Double>{ 14.0583, 108.2772 },
        'PH' => new List<Double>{ 12.8797, 121.7740 },
        'ID' => new List<Double>{ -0.7893, 113.9213 },
        'AU' => new List<Double>{ -25.2744, 133.7751 },
        'NZ' => new List<Double>{ -40.9006, 174.8860 },
        'ZA' => new List<Double>{ -30.5595, 22.9375 },
        'EG' => new List<Double>{ 26.8206, 30.8025 },
        'NG' => new List<Double>{ 9.0820, 8.6753 },
        'KE' => new List<Double>{ -0.0236, 37.9062 },
        'CL' => new List<Double>{ -35.6751, -71.5430 },
        'CO' => new List<Double>{ 4.5709, -74.2973 },
        'PE' => new List<Double>{ -9.1900, -75.0152 }
    };

    /**
     * Returns true when the country code has a centroid in the lookup table.
     */
    public static Boolean isKnown(String countryCode) {
        return countryCode != null && CENTROIDS.containsKey(countryCode.toUpperCase());
    }

    /**
     * Rough great-circle distance in kilometers between two country centroids.
     * Returns null when either country is unknown. Returns 0 when the codes
     * match (same country).
     */
    public static Double roughDistance(String fromCountry, String toCountry) {
        if (fromCountry == null || toCountry == null) {
            return null;
        }
        String a = fromCountry.toUpperCase();
        String b = toCountry.toUpperCase();
        if (a.equals(b)) {
            return 0;
        }
        List<Double> p1 = CENTROIDS.get(a);
        List<Double> p2 = CENTROIDS.get(b);
        if (p1 == null || p2 == null) {
            return null;
        }
        return haversine(p1.get(0), p1.get(1), p2.get(0), p2.get(1));
    }

    /**
     * Haversine formula: great-circle distance between two lat/lon points
     * expressed in kilometers. Apex Math functions take radians.
     */
    private static Double haversine(Double lat1, Double lon1, Double lat2, Double lon2) {
        Double dLat = toRadians(lat2 - lat1);
        Double dLon = toRadians(lon2 - lon1);
        Double rLat1 = toRadians(lat1);
        Double rLat2 = toRadians(lat2);

        Double a =
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(rLat1) * Math.cos(rLat2) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        Double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return EARTH_RADIUS_KM * c;
    }

    private static Double toRadians(Double degrees) {
        return degrees * Math.PI / 180.0;
    }
}
