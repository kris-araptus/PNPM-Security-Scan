import type { APIRoute } from 'astro';
import { scan } from '../../lib/scanner';

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { content, filename } = body;

    if (!content || typeof content !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Missing or invalid content' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    if (!content.trim()) {
      return new Response(
        JSON.stringify({ error: 'Content cannot be empty' }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const result = scan(content, filename || 'package.json');

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Scan failed';
    return new Response(
      JSON.stringify({ error: message }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
};

