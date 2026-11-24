-- عقارات لقطة | مخطط قاعدة البيانات وسياسات الأمان لـ Supabase
-- نفّذ هذا الملف كاملاً في Supabase Dashboard > SQL Editor > New query

create extension if not exists pgcrypto;

-- بيانات الملف الشخصي. الدور الافتراضي عضو، ولا يستطيع العضو ترقيه نفسه.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role text not null default 'member' check (role in ('member','admin')),
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name',''), 'member')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin'
  );
$$;

create table if not exists public.listings (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 3 and 110),
  governorate text not null check (governorate in ('دمشق','ريف دمشق','حلب','حمص','حماة','اللاذقية','طرطوس','إدلب','درعا','السويداء','القنيطرة','دير الزور','الرقة','الحسكة')),
  area text,
  property_type text not null,
  deal_type text not null check (deal_type in ('للبيع','للإيجار')),
  price numeric(18,2) not null check (price >= 0),
  currency text not null default 'ل.س' check (currency in ('ل.س','$','€')),
  area_m2 numeric(12,2),
  rooms integer,
  whatsapp text,
  description text,
  images text[] not null default '{}',
  status text not null default 'pending' check (status in ('pending','published','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists listings_public_sort on public.listings(status, created_at desc);
create index if not exists listings_owner on public.listings(owner_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.listings enable row level security;

-- يمكن للمستخدم قراءة ملفه، والمدير قراءة جميع الملفات. لا توجد سياسة لتعديل role من الواجهة.
drop policy if exists "profile read own or admin" on public.profiles;
create policy "profile read own or admin" on public.profiles
for select to authenticated
using (id = (select auth.uid()) or public.is_admin());

-- الإعلانات المنشورة مرئية للجميع، وصاحب الإعلان والمدير يستطيعان قراءة إعلاناتهما/كل الإعلانات.
drop policy if exists "published listings are public" on public.listings;
create policy "published listings are public" on public.listings
for select to anon, authenticated
using (status = 'published' or owner_id = (select auth.uid()) or public.is_admin());

drop policy if exists "members create own pending listings" on public.listings;
create policy "members create own pending listings" on public.listings
for insert to authenticated
with check (owner_id = (select auth.uid()) and status = 'pending');

-- امنع المعلن من تغيير حالة الإعلان بنفسه، مع السماح له بتعديل تفاصيل إعلان منشور.
create or replace function public.guard_listing_status()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is distinct from old.owner_id
     and not public.is_admin() then
    raise exception 'Not allowed to change this listing';
  end if;
  if not public.is_admin() and new.status is distinct from old.status then
    raise exception 'Only a platform admin can change listing status';
  end if;
  return new;
end;
$$;

drop trigger if exists guard_listing_status_trigger on public.listings;
create trigger guard_listing_status_trigger
before update on public.listings
for each row execute procedure public.guard_listing_status();

drop policy if exists "owners update own listings" on public.listings;
create policy "owners update own listings" on public.listings
for update to authenticated
using (owner_id = (select auth.uid()) or public.is_admin())
with check (owner_id = (select auth.uid()) or public.is_admin());

drop policy if exists "owners or admins delete listings" on public.listings;
create policy "owners or admins delete listings" on public.listings
for delete to authenticated
using (owner_id = (select auth.uid()) or public.is_admin());

-- حاوية الصور العامة: الصور يمكن عرضها للزوار، والرفع/الحذف محصور بصاحب مجلد UUID.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('property-images','property-images',true,5242880,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = true, file_size_limit = 5242880,
allowed_mime_types = array['image/jpeg','image/png','image/webp'];

drop policy if exists "public read property images" on storage.objects;
create policy "public read property images" on storage.objects
for select to anon, authenticated
using (bucket_id = 'property-images');

drop policy if exists "users upload own property images" on storage.objects;
create policy "users upload own property images" on storage.objects
for insert to authenticated
with check (
  bucket_id = 'property-images'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "users delete own property images" on storage.objects;
create policy "users delete own property images" on storage.objects
for delete to authenticated
using (
  bucket_id = 'property-images'
  and ((storage.foldername(name))[1] = (select auth.uid())::text or public.is_admin())
);

-- بعد إنشاء حسابك الأول وتأكيد البريد، شغّل هذا السطر وحده مع استبدال البريد ببريدك:
-- update public.profiles p set role = 'admin'
-- from auth.users u where p.id = u.id and u.email = 'YOUR_EMAIL@example.com';
