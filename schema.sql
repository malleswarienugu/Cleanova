/* =========================================================
   CLEANBRIDGE DATABASE
========================================================= */


/* =========================================================
   PROFILES
========================================================= */

create table if not exists public.profiles (

    id uuid primary key
        references auth.users(id)
        on delete cascade,

    full_name text not null,

    points integer not null default 0,

    reports integer not null default 0,

    cleanups integer not null default 0,

    plastic_collected numeric(10,2)
        not null default 0,

    created_at timestamptz
        not null default now()

);


/* =========================================================
   REPORTS
========================================================= */

create table if not exists public.reports (

    id uuid primary key
        default gen_random_uuid(),

    report_code text unique,

    user_id uuid not null
        references public.profiles(id)
        on delete cascade,

    waste_type text not null,

    quantity text not null,

    severity text not null,

    description text not null,

    latitude double precision,

    longitude double precision,

    photo_path text,

    status text not null
        default 'Pending',

    created_at timestamptz
        not null default now()

);


/* =========================================================
   INDEXES
========================================================= */

create index if not exists
reports_user_id_idx
on public.reports(user_id);


create index if not exists
reports_created_at_idx
on public.reports(created_at);


create index if not exists
reports_status_idx
on public.reports(status);


/* =========================================================
   REPORT CODE
========================================================= */

create sequence if not exists
cleanbridge_report_sequence
start 1001;


create or replace function
public.generate_report_code()
returns trigger
language plpgsql
security definer
set search_path = public
as $$

begin

    if new.report_code is null then

        new.report_code :=
            'CB' ||
            nextval(
                'cleanbridge_report_sequence'
            );

    end if;

    return new;

end;

$$;


drop trigger if exists
generate_report_code_trigger
on public.reports;


create trigger
generate_report_code_trigger

before insert
on public.reports

for each row

execute function
public.generate_report_code();


/* =========================================================
   CREATE PROFILE WHEN USER REGISTERS
========================================================= */

create or replace function
public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$

begin

    insert into public.profiles(
        id,
        full_name
    )

    values(
        new.id,

        coalesce(
            new.raw_user_meta_data
                ->>'full_name',

            'Community Member'
        )
    );

    return new;

end;

$$;


drop trigger if exists
on_auth_user_created
on auth.users;


create trigger
on_auth_user_created

after insert
on auth.users

for each row

execute function
public.handle_new_user();


/* =========================================================
   AUTOMATIC REPORT REWARD
========================================================= */

create or replace function
public.reward_report_submission()
returns trigger
language plpgsql
security definer
set search_path = public
as $$

begin

    update public.profiles

    set

        reports =
            reports + 1,

        points =
            points + 10

    where id =
        new.user_id;


    return new;

end;

$$;


drop trigger if exists
reward_report_trigger
on public.reports;


create trigger
reward_report_trigger

after insert
on public.reports

for each row

execute function
public.reward_report_submission();


/* =========================================================
   ENABLE RLS
========================================================= */

alter table public.profiles
enable row level security;


alter table public.reports
enable row level security;


/* =========================================================
   REMOVE OLD POLICIES IF THEY EXIST
========================================================= */

drop policy if exists
"profiles_select_authenticated"
on public.profiles;


drop policy if exists
"reports_insert_authenticated"
on public.reports;


drop policy if exists
"reports_select_authenticated"
on public.reports;


/* =========================================================
   PROFILE POLICY
========================================================= */

/*
   Authenticated users can view profiles.

   This is needed for the leaderboard.
*/

create policy
"profiles_select_authenticated"

on public.profiles

for select

to authenticated

using(true);


/*
   IMPORTANT:
   There is intentionally NO client update policy
   for points/reports/cleanups.

   Users cannot simply modify their own points
   through browser JavaScript.
*/


/* =========================================================
   REPORT INSERT POLICY
========================================================= */

create policy
"reports_insert_authenticated"

on public.reports

for insert

to authenticated

with check(
    (select auth.uid()) = user_id
);


/* =========================================================
   REPORT SELECT POLICY
========================================================= */

/*
   Authenticated users can see reports on the
   community waste map.

   If you later want private exact locations,
   change this policy and expose only approximate
   locations publicly.
*/

create policy
"reports_select_authenticated"

on public.reports

for select

to authenticated

using(true);


/* =========================================================
   STORAGE BUCKET
========================================================= */

insert into storage.buckets(
    id,
    name,
    public
)

values(
    'report-evidence',
    'report-evidence',
    false
)

on conflict(id)
do nothing;


/* =========================================================
   STORAGE SECURITY
========================================================= */

drop policy if exists
"authenticated_upload_report_evidence"
on storage.objects;


create policy
"authenticated_upload_report_evidence"

on storage.objects

for insert

to authenticated

with check(

    bucket_id =
        'report-evidence'

    and

    (storage.foldername(name))[1] =
        (select auth.uid()::text)

);


/* =========================================================
   USERS CAN READ THEIR OWN EVIDENCE
========================================================= */

drop policy if exists
"users_read_own_report_evidence"
on storage.objects;


create policy
"users_read_own_report_evidence"

on storage.objects

for select

to authenticated

using(

    bucket_id =
        'report-evidence'

    and

    (storage.foldername(name))[1] =
        (select auth.uid()::text)

);


/* =========================================================
   GRANTS
========================================================= */

revoke all
on table public.profiles
from anon;


revoke all
on table public.reports
from anon;


grant select
on public.profiles
to authenticated;


grant select, insert
on public.reports
to authenticated;


/* =========================================================
   FINISHED
========================================================= */