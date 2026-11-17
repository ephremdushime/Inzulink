const availabilityFeedQuery = `
  SELECT
    p.property_id,
    p.title,
    p.description,
    p.district,
    p.sector,
    p.cell,
    p.village,
    p.price_per_month,
    p.bedrooms,
    p.listing_type,
    p.category,
    p.land_size,
    p.status,
    p.is_featured,
    p.video_path,
    p.availability_status,
    p.availability_checked_at,
    p.expires_at,
    u.is_verified_agent,
    COALESCE(json_agg(DISTINCT pi.image_path)
      FILTER (WHERE pi.image_path IS NOT NULL), '[]') AS images,
    COALESCE(AVG(r.rating), 0) AS avg_rating,
    COUNT(DISTINCT r.id) AS review_count
  FROM public.properties p
  JOIN public.users u ON p.owner_id = u.user_id
  LEFT JOIN public.propertyimages pi ON p.property_id = pi.property_id
  LEFT JOIN public.reviews r ON p.property_id = r.property_id
  WHERE p.status = 'Available'
    AND p.is_deleted = FALSE
    AND p.availability_status = 'AVAILABLE'
    AND p.availability_checked_at IS NOT NULL
    AND p.expires_at > NOW()
  GROUP BY p.property_id, u.is_verified_agent
  ORDER BY p.is_featured DESC, p.property_id DESC
`;

const publicAvailabilityFields = [
  "property_id",
  "title",
  "description",
  "district",
  "sector",
  "cell",
  "village",
  "price_per_month",
  "bedrooms",
  "listing_type",
  "category",
  "land_size",
  "status",
  "is_featured",
  "video_path",
  "availability_status",
  "availability_checked_at",
  "expires_at",
  "is_verified_agent",
  "images"
];

function toPublicAvailabilityProperty(row) {
  const property = {};
  for (const field of publicAvailabilityFields) {
    property[field] = row[field];
  }
  if (typeof property.description === "string") {
    property.description = property.description.replace(
      /(?:\+?250[\s().-]*)?(?:0?7[2-9])(?:[\s().-]*\d){7}\b/g,
      "[contact hidden]"
    );
  }
  property.avg_rating = Number(row.avg_rating || 0).toFixed(1);
  property.review_count = Number.parseInt(row.review_count, 10) || 0;
  return property;
}

module.exports = { availabilityFeedQuery, toPublicAvailabilityProperty };
