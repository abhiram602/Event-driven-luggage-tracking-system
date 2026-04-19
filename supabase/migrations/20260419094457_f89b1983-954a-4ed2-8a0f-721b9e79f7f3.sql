-- Drop the old restrictive update policy
DROP POLICY IF EXISTS "Staff can update baggage records at their airport" ON public.baggage_records;

-- Create a security definer helper that checks if the staff's airport is
-- either the bag's current location OR appears in the PNR route_path.
CREATE OR REPLACE FUNCTION public.staff_can_update_bag(_user_id uuid, _pnr_code text, _current_location text)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles ur
    WHERE ur.user_id = _user_id
      AND ur.role IN ('baggage_staff'::app_role, 'checkin_staff'::app_role)
      AND (
        ur.airport_code = _current_location
        OR EXISTS (
          SELECT 1 FROM public.pnr_records p
          WHERE p.pnr_code = _pnr_code
            AND ur.airport_code = ANY(p.route_path)
        )
      )
  )
$$;

-- New permissive update policy: admins, or staff assigned to any airport in the bag's route
CREATE POLICY "Staff can update baggage records on their route"
ON public.baggage_records
FOR UPDATE
TO authenticated
USING (
  public.has_role(auth.uid(), 'admin'::app_role)
  OR public.staff_can_update_bag(auth.uid(), pnr_code, current_location)
);
